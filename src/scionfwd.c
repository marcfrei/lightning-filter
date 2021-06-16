/*
 * Copyright (c) 2021, [fullname]
 * All rights reserved.
 *
 * Based on DPDK examples
 * Copyright (c) 2010-2016 Intel Corporation
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#define RTE_ENABLE_ASSERT 1

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cpuflags.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_gso.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_latencystats.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_metrics.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vect.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

// includes for libraries
#if defined __x86_64__ && __x86_64__
	#include "lib/aesni/aesni.h"
#else
	#include <openssl/evp.h>
#endif

#include "lib/drkey/libdrkey.h"

#include "hashdict_flow.h"
#include "key_dictionary.h"
#include "key_storage.h"
#include "lf_config.h"
#include "measurements.h"
#include "scion_bloom.h"

/* defines */

#define SIMPLE_FORWARD 0

#define ENABLE_KEY_MANAGEMENT 0
#define ENABLE_MEASUREMENTS 0
#define ENFORCE_DUPLICATE_FILTER 0
#define ENFORCE_LF_RATE_LIMIT_FILTER 1
#define LOG_DELEGATION_SECRETS 0
#define LOG_PACKETS 0
#define CHECK_PACKET_STRUCTURE 0

// deployment
#define UNIDIRECTIONAL_SETUP 1
#define AWS_DEPLOYMENT 0

// logging
#define RTE_LOGTYPE_scionfwd RTE_LOGTYPE_USER1

// Lightning Filter Port
#define LF_DEFAULT_PORT 49149

// Bloom Filter
#define MAX_BLOOM_FILTERS 2
#define MAX_SUPPORTED_PORTS 16

// Metrics IPC Socket
#define ADDRESS "/tmp/echo.sock"

// States for DOS
#define EVEN 0
#define ODD 1

// queue params
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 128
#define MAX_RX_QUEUE_PER_PORT 128

// lcore params
#define MAX_LCORE_PARAMS 1024
#define MAX_NB_SOCKETS 8

// memory and drain params
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

// Configurable number of RX/TX ring descriptors
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

// Key manager constants
#define DEFAULT_KEY_DICTIONARY_SIZE (32)

// Protocol specific constants
#define IP_TTL_DEFAULT 0xff
#define IP_PROTO_ID_TCP 0x06
#define IP_PROTO_ID_UDP 0x11
#define IPV4_VERSION 0x4

// Cryptography related constants
#define BLOCK_SIZE 16
#define IV_SIZE 16

/**
 * LF Header
 */
struct lf_hdr {
	uint8_t lf_pkt_type;
	uint8_t reserved[3];
	uint64_t src_ia;
	uint8_t encaps_pkt_chksum[16];
	uint16_t encaps_pkt_len;
} __attribute__((__packed__));

/* MAIN DATA STRUCTS */

// cycle count struct, used by each core to collect cycle counts
struct measurements measurements[RTE_MAX_LCORE];

/* mempool, we have one mempool for each socket, shared by
 * all cores on that socket */
static struct rte_mempool *scionfwd_pktmbuf_pool[MAX_NB_SOCKETS];

// core statistic struct
struct core_stats {
	uint64_t rx_counter;
	uint64_t tx_bypass_counter;
	uint64_t tx_firewall_counter;
	uint64_t key_mismatch_counter;
	uint64_t secX_fail_counter;
	uint64_t bloom_filter_hit_counter;
	uint64_t bloom_filter_miss_counter;
	uint64_t as_rate_limited;
	uint64_t rate_limited;
} __rte_cache_aligned;

// core runtime struct
typedef struct lcore_values {
	struct core_stats stats; /* core stats object */
	struct rte_gso_ctx gso_ctx; /**< GSO context */
	struct rte_mempool *mbp; /**< The mbuf pool to use by this core */
	struct bloom bloom_filters[MAX_BLOOM_FILTERS];
	uint64_t active_filter_id;
	struct timeval last_ts, cur_ts;
	struct rte_eth_dev_tx_buffer *tx_bypass_buffer;
	struct rte_eth_dev_tx_buffer *tx_firewall_buffer;
	uint8_t socket_id;
	uint8_t rx_port_id;
	uint8_t rx_queue_id;
	uint8_t tx_bypass_port_id;
	uint8_t tx_firewall_port_id;
	uint16_t tx_bypass_queue_id;
	uint16_t tx_firewall_queue_id;
} lcore_values;
struct lcore_values core_vars[RTE_MAX_LCORE];

// port runtime struct
typedef struct port_values {
	uint8_t socket_id;
	uint32_t nb_slave_cores;
	struct rte_eth_dev_info dev_info; /**< PCI info + driver name */
	struct rte_eth_conf dev_conf; /**< Port configuration. */
	struct rte_ether_addr eth_addr; /**< Port ethernet address */
	struct rte_eth_stats stats; /**< Last port statistics */
	uint8_t rx_slave_core_ids[RTE_MAX_LCORE]; /* ids of all rx cores allocated to this port */
	uint8_t tx_slave_core_ids[RTE_MAX_LCORE]; /* ids of all tx cores allocated to this port */
} port_values;
struct port_values port_vars[RTE_MAX_ETHPORTS];

/* denial of service statistic struct
 * used by the rate-limiter, each struct field is an array of two,
 * for both the even and the odd state */
typedef struct dos_statistic {
	dictionary_flow *dos_dictionary[2];
	int64_t secX_dos_packet_count[2];
	int64_t sc_dos_packet_count[2];
	rte_atomic64_t *reserve[2];
} dos_statistic;

/* array contatining the dos stat structs for each core,
 * once for the current period and once for the previous */
struct dos_statistic dos_stats[RTE_MAX_LCORE];
struct dos_statistic previous_dos_stat[RTE_MAX_LCORE];

// DPDK NIC configuration
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN, /* max packet length capped to ETHERNET MTU */
		.split_hdr_size = 0,
	},
	.rx_adv_conf = {
		.rss_conf = { /* configuration according to NIC capability */
			.rss_key = NULL,
#if AWS_DEPLOYMENT
			.rss_hf = ETH_RSS_IPV4
				| ETH_RSS_FRAG_IPV4
				| ETH_RSS_NONFRAG_IPV4_TCP
				| ETH_RSS_NONFRAG_IPV4_UDP
				// | ETH_RSS_NONFRAG_IPV4_SCTP
				| ETH_RSS_NONFRAG_IPV4_OTHER
				| ETH_RSS_FRAG_IPV6
				| ETH_RSS_NONFRAG_IPV6_TCP
				| ETH_RSS_NONFRAG_IPV6_UDP
				// | ETH_RSS_NONFRAG_IPV6_SCTP
				| ETH_RSS_NONFRAG_IPV6_OTHER
				// | ETH_RSS_L2_PAYLOAD
				| ETH_RSS_IPV6_EX
				| ETH_RSS_IPV6_TCP_EX
				| ETH_RSS_IPV6_UDP_EX
#else
			.rss_hf = ETH_RSS_FRAG_IPV4
				| ETH_RSS_NONFRAG_IPV4_TCP
				| ETH_RSS_NONFRAG_IPV4_UDP
				| ETH_RSS_NONFRAG_IPV4_SCTP
				| ETH_RSS_NONFRAG_IPV4_OTHER
				| ETH_RSS_FRAG_IPV6
				| ETH_RSS_NONFRAG_IPV6_TCP
				| ETH_RSS_NONFRAG_IPV6_UDP
				| ETH_RSS_NONFRAG_IPV6_SCTP
				| ETH_RSS_NONFRAG_IPV6_OTHER
				| ETH_RSS_L2_PAYLOAD
#endif
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
		.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM,
	},
};

/* global variables */

// force quit flag, will be set to true by signal handlers
// all threads will stop if flag has been set and application will terminate
static volatile bool force_quit;

// global atomic that stores the current state of the rate-limiter
static rte_atomic16_t dos_state;

// ports
uint8_t nb_ports;
uint8_t nb_rx_ports;
uint8_t nb_tx_ports;
uint8_t nb_tx_bypass_ports;
uint8_t nb_tx_firewall_ports;

// port type bitmaps
bool is_active_port[RTE_MAX_ETHPORTS];
bool is_rx_port[RTE_MAX_ETHPORTS];
bool is_tx_bypass_port[RTE_MAX_ETHPORTS];
bool is_tx_firewall_port[RTE_MAX_ETHPORTS];

// lcores
uint32_t nb_cores;
uint32_t nb_slave_cores;

// core type bitmaps
bool is_dos_core[RTE_MAX_LCORE];
bool is_key_manager_core[RTE_MAX_LCORE];
bool is_metrics_core[RTE_MAX_LCORE];
bool is_slave_core[RTE_MAX_LCORE];
bool is_in_use[RTE_MAX_LCORE];

// key manager
uint32_t key_manager_core_id; /* cpu_id of the key manager core */
struct key_dictionary
	*key_dictionaries[RTE_MAX_LCORE]; /* holds pointer to the key dictionary of each core */

// used to store key struct, roundkeys, computed CMAC and packet CMAC
// in CMAC computation. Memory allocation at main loop start
// (initialization start). Overwritten in each computation (reuse for
// efficiency)
unsigned char *key_hosts_addrs[RTE_MAX_LCORE]; /* address buffers for lvl2 key derviation */
unsigned char *roundkey[RTE_MAX_LCORE]; /* buffer to store AES round keys */
unsigned char *computed_cmac[RTE_MAX_LCORE]; /* buffers to store the computed CMAC of a packet */

#if !(defined __x86_64__ && __x86_64__)
EVP_CIPHER_CTX *cipher_ctx[RTE_MAX_LCORE];
#endif

/* Global pools for the rate-limiter
 * one pool is fr SecX traffic the other for normal SCION traffic */
int64_t current_pool[2];

/* system configuration */

// mask of receiving ports
static uint32_t scionfwd_rx_port_mask = 0;

// mask of bypass ports
static uint32_t scionfwd_tx_bypass_port_mask = 0;

// mask of firewall ports
static uint32_t scionfwd_tx_firewall_port_mask = 0;

// blooom filter config
uint64_t NUM_BLOOM_ENTRIES = 700000;
uint64_t BLOOM_ERROR_RATE = 10000;
int delta_us = 2500000;
int BLOOM_FILTERS = 2;

// rate-limiter config */
static uint64_t MAX_POOL_SIZE_FACTOR = 5; /* max allowd pool size (determines max paket burst) */
static double RESERVE_FRACTION =
	0.03; /* fraction of rate-limit allocation stored in shared reserve */

// MAC updating enabled by default
// (deprecated)
static int mac_updating = 0;

// NUMA allocation enabled by default
static int numa_on = 0;

// interactive CLI disabled by default
static int is_interactive;

// Configuration loaded from config file
static struct lf_config config;

/* tsc-based timers responsible for triggering actions */
uint64_t tsc_hz; /* only for cycle counting */
static uint64_t slice_timer_period = 1800; /* #seconds for each bucket, scaled to hertz */
static uint64_t slice_timer_period_seconds = 1800; /* #seconds for each bucket, unscaled, seconds */
static uint64_t dos_slice_period; /* length of a rate limit slice (100 micro seconds) */

/* number of packets that the host wants to receive maximally. 0 if no limit
 * limit is number of packets per second
 * (deprecated)
 */
uint64_t receive_limit = UINT64_MAX;

#if LOG_PACKETS
/* Adapted from: https://github.com/NEOAdvancedTechnology/MinimalDPDKExamples
 *
 * Copyright(c) 2010-2015 Intel Corporation
 */
static void dump_hex(const unsigned lcore_id, const void *data, size_t size) {
	char ascii[17];
	int lf = 1;
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		if (lf) {
			printf("[%d] ", lcore_id);
			lf = 0;
		}
		printf("%02X ", ((const unsigned char *)data)[i]);
		if (((const unsigned char *)data)[i] >= ' ' && ((const unsigned char *)data)[i] <= '~') {
			ascii[i % 16] = ((const unsigned char *)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
				lf = 1;
			} else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
				lf = 1;
			}
		}
	}
}
#endif

/*
 * crypto_cmp_16 returns 0 if x[0], x[1], ..., x[15] are the same as y[0],
 * y[1], ..., y[15]. Otherwise it returns -1.
 *
 * See https://nacl.cr.yp.to/verify.html
 * and https://tweetnacl.cr.yp.to/
 */
static int crypto_cmp_16(const void *x, const void *y) {
	const unsigned char *a = x, *b = y;
	uint32_t d = 0;
	d |= a[0] ^ b[0];
	d |= a[1] ^ b[1];
	d |= a[2] ^ b[2];
	d |= a[3] ^ b[3];
	d |= a[4] ^ b[4];
	d |= a[5] ^ b[5];
	d |= a[6] ^ b[6];
	d |= a[7] ^ b[7];
	d |= a[8] ^ b[8];
	d |= a[9] ^ b[9];
	d |= a[10] ^ b[10];
	d |= a[11] ^ b[11];
	d |= a[12] ^ b[12];
	d |= a[13] ^ b[13];
	d |= a[14] ^ b[14];
	d |= a[15] ^ b[15];
	return (1 & ((d - 1) >> 8)) - 1;
}

#if 0
static void
setfwd_eth_addrs(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	uint8_t dst[] = {0x0a, 0x69, 0xb4, 0xe8, 0x18, 0xbc};

	(void)rte_memcpy(eth->s_addr.addr_bytes, eth->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	(void)rte_memcpy(eth->d_addr.addr_bytes, dst, RTE_ETHER_ADDR_LEN);
}
#endif

static void swap_eth_addrs(struct rte_mbuf *m) {
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	uint8_t tmp[RTE_ETHER_ADDR_LEN];

	(void)rte_memcpy(tmp, eth->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	(void)rte_memcpy(eth->d_addr.addr_bytes, eth->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	(void)rte_memcpy(eth->s_addr.addr_bytes, tmp, RTE_ETHER_ADDR_LEN);
}

static int find_backend(rte_be32_t private_addr, struct lf_config_backend *b) {
	struct lf_config_backend *x = config.backends;
	while ((x != NULL) && (x->private_addr != (int32_t)private_addr)) {
		x = x->next;
	}
	if (x != NULL) {
		if (b != NULL) {
			*b = *x;
		}
		return 1;
	} else {
		return 0;
	}
}

static int find_peer(rte_be32_t public_addr, struct lf_config_peer *p) {
	struct lf_config_peer *x = config.peers;
	while ((x != NULL) && (x->public_addr != (int32_t)public_addr)) {
		x = x->next;
	}
	if (x != NULL) {
		if (p != NULL) {
			*p = *x;
		}
		return 1;
	} else {
		return 0;
	}
}

static int is_backend(rte_be32_t private_addr) {
	return find_backend(private_addr, NULL);
}

static int is_peer(rte_be32_t public_addr) {
	return find_peer(public_addr, NULL);
}

static rte_be32_t backend_public_addr(rte_be32_t private_addr) {
	struct lf_config_backend b;
	int r = find_backend(private_addr, &b);
	RTE_ASSERT(r != 0);
	return b.public_addr;
}

static struct delegation_secret *get_delegation_secret(struct key_store_node *n, int64_t t) {
	struct delegation_secret *ds = &n->key_store->delegation_secrets[n->key_index];
	if ((ds->validity_not_before >= ds->validity_not_after) || (t < ds->validity_not_before)
			|| (ds->validity_not_after < t))
	{
		n->key_index = NEXT_KEY_INDEX(n->key_index);
		ds = &n->key_store->delegation_secrets[n->key_index];
		if ((ds->validity_not_before >= ds->validity_not_after) || (t < ds->validity_not_before)
				|| (ds->validity_not_after < t))
		{
			n->key_index = NEXT_KEY_INDEX(n->key_index);
			ds = &n->key_store->delegation_secrets[n->key_index];
			if ((ds->validity_not_before >= ds->validity_not_after) || (t < ds->validity_not_before)
					|| (ds->validity_not_after < t))
			{
				return NULL;
			}
		}
	}
	return ds;
}

static void compute_lf_chksum(const unsigned lcore_id, unsigned char drkey[BLOCK_SIZE], rte_be32_t src_addr,
	rte_be32_t dst_addr, void *data, size_t data_len, unsigned char chksum[BLOCK_SIZE],
	unsigned char rkey_buf[10 * BLOCK_SIZE], unsigned char addr_buf[32]) {

	RTE_ASSERT(data_len % BLOCK_SIZE == 0);
	RTE_ASSERT(data_len <= INT_MAX);
	(void)memset(addr_buf, 0, 32);
	(void)rte_memcpy(addr_buf, &src_addr, sizeof src_addr);
	(void)rte_memcpy(addr_buf + 16, &dst_addr, sizeof dst_addr);

#if defined __x86_64__ && __x86_64__
	(void)lcore_id;

	// derive the second-order key based on the first order key
	(void)memset(rkey_buf, 0, 10 * BLOCK_SIZE);
	(void)ExpandKey128(drkey, rkey_buf);
	(void)CBCMAC(rkey_buf, 32 / BLOCK_SIZE, addr_buf, chksum);

	// compute per-packet MAC using the second-order key
	(void)memset(rkey_buf, 0, 10 * BLOCK_SIZE);
	(void)ExpandKey128(chksum, rkey_buf);
	(void)CBCMAC(rkey_buf, data_len / BLOCK_SIZE, data, chksum);
#else
	(void)rkey_buf;

	int r, n;
	unsigned char key[BLOCK_SIZE], iv[IV_SIZE];

	EVP_CIPHER_CTX *ctx = cipher_ctx[lcore_id];

	// derive the second-order key based on the first order key
	(void)rte_memcpy(key, drkey, BLOCK_SIZE);
	(void)memset(iv, 0, IV_SIZE);
	r = EVP_CIPHER_CTX_reset(ctx);
	RTE_ASSERT(r == 1);
	r = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
	RTE_ASSERT(r == 1);
	r = EVP_CIPHER_CTX_set_padding(ctx, 0);
	RTE_ASSERT(r == 1);
	r = EVP_EncryptUpdate(ctx, chksum, &n, addr_buf, 32);
	RTE_ASSERT((r == 1) && (n == 32));
	r = EVP_EncryptFinal_ex(ctx, &chksum[n], &n);
	RTE_ASSERT((r == 1) && (n == 0));

	// compute per-packet MAC using the second-order key
	(void)rte_memcpy(key, chksum, BLOCK_SIZE);
	(void)memset(iv, 0, IV_SIZE);
	r = EVP_CIPHER_CTX_reset(ctx);
	RTE_ASSERT(r == 1);
	r = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
	RTE_ASSERT(r == 1);
	r = EVP_CIPHER_CTX_set_padding(ctx, 0);
	RTE_ASSERT(r == 1);
	r = EVP_EncryptUpdate(ctx, chksum, &n, data, (int)data_len);
	RTE_ASSERT((r == 1) && (n == (int)data_len));
	r = EVP_EncryptFinal_ex(ctx, &chksum[n], &n);
	RTE_ASSERT((r == 1) && (n == 0));
#endif
}

static int handle_inbound_pkt(struct rte_mbuf *m, struct rte_ether_hdr *ether_hdr0,
	struct rte_ipv4_hdr *ipv4_hdr0, const unsigned lcore_id, struct lcore_values *lvars,
	int16_t state) {
	uint16_t ipv4_total_length0 = rte_be_to_cpu_16(ipv4_hdr0->total_length);

	int lf_pkt = 0;

	if (is_peer(ipv4_hdr0->src_addr) && (ipv4_hdr0->next_proto_id == IP_PROTO_ID_UDP)) {
		uint16_t ipv4_hdr_length0 =
			(ipv4_hdr0->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

#if CHECK_PACKET_STRUCTURE
		if (unlikely(ipv4_hdr_length0 < sizeof *ipv4_hdr0)) {
			// #if LOG_PACKETS
			printf("[%d] Invalid IP packet: header length too small.\n", lcore_id);
			// #endif
			return -1;
		}
#endif
#if CHECK_PACKET_STRUCTURE
		if (unlikely(ipv4_hdr_length0 > m->data_len - sizeof *ether_hdr0)) {
			// #if LOG_PACKETS
			printf("[%d] Not yet implemented: IP header exceeds first buffer segment.\n", lcore_id);
			// #endif
			return -1;
		}
#endif

		struct rte_udp_hdr *udp_hdr;
#if CHECK_PACKET_STRUCTURE
		if (unlikely(sizeof *udp_hdr > m->data_len - sizeof *ether_hdr0 - ipv4_hdr_length0)) {
			// #if LOG_PACKETS
			printf("[%d] Not yet implemented: UDP header exceeds first buffer segment.\n", lcore_id);
			// #endif
			return -1;
		}
#endif
		udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr0 + ipv4_hdr_length0);

		uint16_t dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
		if ((LF_DEFAULT_PORT <= dst_port) && (dst_port < LF_DEFAULT_PORT + 128)) {
			lf_pkt = 1;

#if CHECK_PACKET_STRUCTURE
			if (unlikely(ipv4_total_length0 != m->data_len - sizeof *ether_hdr0)) {
				// #if LOG_PACKETS
				printf(
					"[%d] Not yet implemented: IP packet length does not match with first buffer segment "
					"length.\n",
					lcore_id);
				// #endif
				return -1;
			}
#endif

			uint16_t ipv4_data_length0 = ipv4_total_length0 - ipv4_hdr_length0;

			rte_be32_t ipv4_hdr_src_addr0 = ipv4_hdr0->src_addr;
			rte_be32_t ipv4_hdr_dst_addr0 = ipv4_hdr0->dst_addr;

			uint16_t udp_dgram_length = rte_be_to_cpu_16(udp_hdr->dgram_len);
#if CHECK_PACKET_STRUCTURE
			if (unlikely(udp_dgram_length != ipv4_data_length0)) {
				// #if LOG_PACKETS
				printf("[%d] Invalid IP packet: total length inconsistent with UDP datagram length.\n",
					lcore_id);
				// #endif
				return -1;
			}
#else
			(void)ipv4_data_length0;
			(void)udp_dgram_length;
#endif
#if CHECK_PACKET_STRUCTURE
			if (unlikely(udp_dgram_length < sizeof *udp_hdr)) {
				// #if LOG_PACKETS
				printf("[%d] Invalid UDP packet: datagram length smaller than header length.\n", lcore_id);
				// #endif
				return -1;
			}
#endif

			struct lf_hdr *lf_hdr;
#if CHECK_PACKET_STRUCTURE
			if (unlikely(sizeof *lf_hdr > udp_dgram_length - sizeof *udp_hdr)) {
				// #if LOG_PACKETS
				printf("[%d] Invalid LF packet: LF header exceeds datagram length.\n", lcore_id);
				// #endif
				return -1;
			}
#endif
			lf_hdr = (struct lf_hdr *)(udp_hdr + 1);

			uint16_t encaps_pkt_len = rte_be_to_cpu_16(lf_hdr->encaps_pkt_len);
#if CHECK_PACKET_STRUCTURE
			if (unlikely(encaps_pkt_len > udp_dgram_length - sizeof *udp_hdr - sizeof *lf_hdr)) {
				// #if LOG_PACKETS
				printf("[%d] Invalid LF packet: encapsulated packet length exceeds datagram length.\n",
					lcore_id);
				// #endif
				return -1;
			}
#endif

			// compute trailer length such that we get a multiple of 16 as data input size
			uint16_t encaps_trl_len = (16 - (sizeof lf_hdr->encaps_pkt_len + encaps_pkt_len) % 16) % 16;
			if (encaps_trl_len != 0) {
				char *p = rte_pktmbuf_append(m, encaps_trl_len);
				RTE_ASSERT(p == (char *)(lf_hdr + 1) + encaps_pkt_len);
				(void)memset(p, 0, encaps_trl_len);
			}
			unsigned char *chksum = computed_cmac[lcore_id];

			struct timeval tv_now;
			int r = gettimeofday(&tv_now, NULL);
			if (unlikely(r != 0)) {
				RTE_ASSERT(r == -1);
				// #if LOG_PACKETS
				printf("[%d] Syscall gettimeofday failed.\n", lcore_id);
				// #endif
				return -1;
			}
			RTE_ASSERT((INT64_MIN <= tv_now.tv_sec) && (tv_now.tv_sec <= INT64_MAX));
			int64_t t_now = tv_now.tv_sec;

			struct key_dictionary *d = key_dictionaries[lcore_id];
			key_dictionary_find(d, lf_hdr->src_ia);
			struct key_store_node *n = d->value;
			if (unlikely(n == NULL)) {
				// #if LOG_PACKETS
				printf("[%d] Key store lookup failed.\n", lcore_id);
				// #endif
				return -1;
			}
			struct delegation_secret *ds = get_delegation_secret(n, t_now);
			if (unlikely(ds == NULL)) {
				// #if LOG_PACKETS
				printf("[%d] Delegation secret lookup failed.\n", lcore_id);
				// #endif
				return -1;
			}
#if LOG_PACKETS
			printf("[%d] DRKey for %0lx at %ld: {\n", lcore_id, lf_hdr->src_ia, t_now);
			dump_hex(lcore_id, ds->key, 16);
			printf("[%d] }\n", lcore_id);
#endif

			compute_lf_chksum(lcore_id,
				/* drkey: */ ds->key,
				/* src_addr: */ ipv4_hdr_src_addr0,
				/* dst_addr: */ backend_public_addr(ipv4_hdr_dst_addr0),
				/* data: */ &lf_hdr->encaps_pkt_len,
				/* data_len: */ sizeof lf_hdr->encaps_pkt_len + encaps_pkt_len + encaps_trl_len,
				/* chksum: */ chksum,
				/* rkey_buf: */ roundkey[lcore_id],
				/* addr_buf: */ key_hosts_addrs[lcore_id]);
			bool is_chksum_valid = crypto_cmp_16(lf_hdr->encaps_pkt_chksum, chksum) == 0;

			if (unlikely(
						!is_chksum_valid && (ds->validity_not_after - t_now < max_key_validity_extension))) {
				// the current delegation secret has expired -> try again with the next delegation secret
				ds = &n->key_store->delegation_secrets[NEXT_KEY_INDEX(n->key_index)];
				if (ds->validity_not_before < ds->validity_not_after) {
#if LOG_PACKETS
					printf("[%d] DRKey for %0lx at %ld: {\n", lcore_id, lf_hdr->src_ia, t_now);
					dump_hex(lcore_id, ds->key, 16);
					printf("[%d] }\n", lcore_id);
#endif
					compute_lf_chksum(lcore_id,
						/* drkey: */ ds->key,
						/* src_addr: */ ipv4_hdr_src_addr0,
						/* dst_addr: */ backend_public_addr(ipv4_hdr_dst_addr0),
						/* data: */ &lf_hdr->encaps_pkt_len,
						/* data_len: */ sizeof lf_hdr->encaps_pkt_len + encaps_pkt_len + encaps_trl_len,
						/* chksum: */ chksum,
						/* rkey_buf: */ roundkey[lcore_id],
						/* addr_buf: */ key_hosts_addrs[lcore_id]);
					is_chksum_valid = crypto_cmp_16(lf_hdr->encaps_pkt_chksum, chksum) == 0;
				}
			}
			if (unlikely(
						!is_chksum_valid && (t_now - ds->validity_not_before < max_key_validity_extension))) {
				// the current delegation secret is not valid yet -> try again with the previous delegation secret
				ds = &n->key_store->delegation_secrets[PREV_KEY_INDEX(n->key_index)];
				if (ds->validity_not_before < ds->validity_not_after) {
#if LOG_PACKETS
					printf("[%d] DRKey for %0lx at %ld: {\n", lcore_id, lf_hdr->src_ia, t_now);
					dump_hex(lcore_id, ds->key, 16);
					printf("[%d] }\n", lcore_id);
#endif
					compute_lf_chksum(lcore_id,
						/* drkey: */ ds->key,
						/* src_addr: */ ipv4_hdr_src_addr0,
						/* dst_addr: */ backend_public_addr(ipv4_hdr_dst_addr0),
						/* data: */ &lf_hdr->encaps_pkt_len,
						/* data_len: */ sizeof lf_hdr->encaps_pkt_len + encaps_pkt_len + encaps_trl_len,
						/* chksum: */ chksum,
						/* rkey_buf: */ roundkey[lcore_id],
						/* addr_buf: */ key_hosts_addrs[lcore_id]);
					is_chksum_valid = crypto_cmp_16(lf_hdr->encaps_pkt_chksum, chksum) == 0;
				}
			}
			if (unlikely(!is_chksum_valid)) {
				// #if LOG_PACKETS
				printf("[%d] Invalid LF packet: checksum verification failed.\n", lcore_id);
				// #endif
				return -1;
			}
			if (encaps_trl_len != 0) {
				int r = rte_pktmbuf_trim(m, encaps_trl_len);
				RTE_ASSERT(r == 0);
			}

			struct lcore_values *lcore_values = &core_vars[lcore_id];

			// Periodically rotate and reset the bloom filters to avoid overcrowding
			lcore_values->cur_ts = tv_now;
			if ((lcore_values->cur_ts.tv_sec - lcore_values->last_ts.tv_sec) * 1000000
						+ lcore_values->cur_ts.tv_usec - lcore_values->last_ts.tv_usec
					> delta_us)
			{
				lcore_values->active_filter_id = (lcore_values->active_filter_id + 1) % MAX_BLOOM_FILTERS;
				bloom_free(&lcore_values->bloom_filters[lcore_values->active_filter_id]);
				bloom_init(&lcore_values->bloom_filters[lcore_values->active_filter_id], NUM_BLOOM_ENTRIES,
					1.0 / BLOOM_ERROR_RATE);
				lcore_values->last_ts = lcore_values->cur_ts;
			}
			int dup = sc_bloom_add(
				lcore_values->bloom_filters, MAX_BLOOM_FILTERS, lcore_values->active_filter_id, chksum, 16);
			if (dup != 0) {
				lcore_values->stats.bloom_filter_hit_counter++;
#if ENFORCE_DUPLICATE_FILTER
				// #if LOG_PACKETS
				printf("[%d] Duplicate LF packet.\n", lcore_id);
				// #endif
				return -1;
#endif
			} else {
				lcore_values->stats.bloom_filter_miss_counter++;
			}

			uint16_t encaps_hdr_len = ipv4_hdr_length0 + sizeof *udp_hdr + sizeof *lf_hdr;

			RTE_ASSERT(sizeof *ether_hdr0 <= encaps_hdr_len);
			struct rte_ether_hdr *ether_hdr1 =
				rte_memcpy((char *)ether_hdr0 + encaps_hdr_len, ether_hdr0, sizeof *ether_hdr0);

			char *p = rte_pktmbuf_adj(m, encaps_hdr_len);
			RTE_ASSERT(p != NULL);

			RTE_ASSERT(p == (char *)ether_hdr1);

			RTE_ASSERT(sizeof *ether_hdr1 <= m->data_len);
			struct rte_ipv4_hdr *ipv4_hdr1 = (struct rte_ipv4_hdr *)(ether_hdr1 + 1);

			RTE_ASSERT(sizeof *ipv4_hdr1 <= m->data_len - sizeof *ether_hdr1);

			uint16_t ipv4_total_length1 = rte_be_to_cpu_16(ipv4_hdr1->total_length);
			RTE_ASSERT(ipv4_total_length1 == m->data_len - sizeof *ether_hdr1);

#if ENFORCE_LF_RATE_LIMIT_FILTER
			dictionary_flow *lcore_dict = dos_stats[lcore_id].dos_dictionary[state];
			r = dic_find_flow(lcore_dict, lf_hdr->src_ia);
			RTE_ASSERT(r == 1);

			// Rate limit LF traffic
			if (lcore_dict->value->secX_counter <= 0) {
				if (lcore_dict->value->sc_counter <= 0) {
					int64_t reserve = rte_atomic64_read(lcore_dict->value->reserve);
					if (reserve <= 0) {
						lcore_values->stats.as_rate_limited++;
	#if LOG_PACKETS
						printf("[%d] LF rate limit for %0lx exceeded.\n", lcore_id, lf_hdr->src_ia);
	#endif
						return -1;
					} else {
						rte_atomic64_sub(lcore_dict->value->reserve, ipv4_total_length1);
					}
				} else {
					lcore_dict->value->sc_counter -= ipv4_total_length1;
				}
			} else {
				lcore_dict->value->secX_counter -= ipv4_total_length1;
			}
			// Check then for overall rate
			if (dos_stats[lcore_id].secX_dos_packet_count[state] <= 0) {
				if (dos_stats[lcore_id].sc_dos_packet_count[state] <= 0) {
					int64_t reserve = rte_atomic64_read(dos_stats[lcore_id].reserve[state]);
					if (reserve <= 0) {
						lcore_values->stats.rate_limited++;
	#if LOG_PACKETS
						printf("[%d] LF overall rate limit for %0lx exceeded.\n", lcore_id, lf_hdr->src_ia);
	#endif
						return -1;
					} else {
						rte_atomic64_sub(dos_stats[lcore_id].reserve[state], ipv4_total_length1);
					}
				} else {
					dos_stats[lcore_id].sc_dos_packet_count[state] -= ipv4_total_length1;
				}
			} else {
				dos_stats[lcore_id].secX_dos_packet_count[state] -= ipv4_total_length1;
			}
#endif

			ipv4_hdr1->hdr_checksum = 0;
			ipv4_hdr1->src_addr = ipv4_hdr_src_addr0;
			ipv4_hdr1->dst_addr = ipv4_hdr_dst_addr0;

			m->l2_len = sizeof *ether_hdr1;
			m->l3_len = sizeof *ipv4_hdr1;
			m->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;

			if (ipv4_hdr1->next_proto_id == IP_PROTO_ID_UDP) {
				struct rte_udp_hdr *udp_hdr;
				RTE_ASSERT(sizeof *udp_hdr <= m->data_len - sizeof *ether_hdr1 - sizeof *ipv4_hdr1);
				udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr1 + 1);
				udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr1, /* ol_flags: */ 0);
				m->ol_flags |= PKT_TX_UDP_CKSUM;
			} else if (ipv4_hdr1->next_proto_id == IP_PROTO_ID_TCP) {
				struct rte_tcp_hdr *tcp_hdr;
				RTE_ASSERT(sizeof *tcp_hdr <= m->data_len - sizeof *ether_hdr1 - sizeof *ipv4_hdr1);
				tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr1 + 1);
				tcp_hdr->cksum = rte_ipv4_phdr_cksum(ipv4_hdr1, /* ol_flags: */ 0);
				m->ol_flags |= PKT_TX_TCP_CKSUM;
			}
		}
	}

	if (lf_pkt == 0) {
		struct lcore_values *lcore_values = &core_vars[lcore_id];
		dictionary_flow *lcore_dict = dos_stats[lcore_id].dos_dictionary[state];

		int r = dic_find_flow(lcore_dict, 0);
		RTE_ASSERT(r == 1);

		// Rate limit non-LF traffic
		if (lcore_dict->value->sc_counter <= 0) {
			lcore_values->stats.as_rate_limited++;
#if LOG_PACKETS
			printf("[%d] Non-LF rate limit exceeded.\n", lcore_id);
#endif
			return -1;
		} else {
			lcore_dict->value->sc_counter -= ipv4_total_length0;
		}
		// Check then for overall rate
		if (dos_stats[lcore_id].sc_dos_packet_count[state] <= 0) {
			lcore_values->stats.rate_limited++;
#if LOG_PACKETS
			printf("[%d] Non-LF overall rate limit exceeded.\n", lcore_id);
#endif
			return -1;
		} else {
			dos_stats[lcore_id].sc_dos_packet_count[state] -= ipv4_total_length0;
		}
	}

#if !UNIDIRECTIONAL_SETUP
	swap_eth_addrs(m);
#endif

#if LOG_PACKETS
	printf("[%d] Forwarding incoming packet:\n", lcore_id);
	dump_hex(lcore_id, rte_pktmbuf_mtod(m, char *), m->pkt_len);
#endif
	uint16_t n = rte_eth_tx_buffer(
		lvars->tx_bypass_port_id, lvars->tx_bypass_queue_id, lvars->tx_bypass_buffer, m);
	(void)n;
#if LOG_PACKETS
	if (n > 0) {
		printf("[%d] Flushed packets to TX port: %d\n", lcore_id, n);
	}
#endif

	return 0;
}

static int handle_outbound_pkt(struct rte_mbuf *m, struct rte_ether_hdr *ether_hdr0,
	struct rte_ipv4_hdr *ipv4_hdr0, const unsigned lcore_id, struct lcore_values *lvars) {
	if (is_peer(ipv4_hdr0->dst_addr)) {
		uint16_t ipv4_total_length0 = rte_be_to_cpu_16(ipv4_hdr0->total_length);

		if (unlikely(ipv4_total_length0 != m->data_len - sizeof *ether_hdr0)) {
			// #if LOG_PACKETS
			printf(
				"[%d] Not yet implemented: IP packet length does not match with first buffer segment "
				"length.\n",
				lcore_id);
			// #endif
			return -1;
		}

		struct rte_ipv4_hdr *ipv4_hdr1;
		struct rte_udp_hdr *udp_hdr;
		struct lf_hdr *lf_hdr;
		RTE_ASSERT(sizeof *ipv4_hdr1 <= UINT16_MAX);
		RTE_ASSERT(sizeof *udp_hdr <= UINT16_MAX - sizeof *ipv4_hdr1);
		RTE_ASSERT(sizeof *lf_hdr <= UINT16_MAX - sizeof *ipv4_hdr1 - sizeof *udp_hdr);
		uint16_t encaps_hdr_len = sizeof *ipv4_hdr1 + sizeof *udp_hdr + sizeof *lf_hdr;

		RTE_ASSERT(sizeof lf_hdr->encaps_pkt_len <= UINT16_MAX);
		if (unlikely((uint16_t)(sizeof lf_hdr->encaps_pkt_len) > UINT16_MAX - ipv4_total_length0)) {
			// #if LOG_PACKETS
			printf("[%d] Not yet implemented: LF packet too big to encapsulate.\n", lcore_id);
			// #endif
			return -1;
		}

		uint16_t encaps_trl_len = (16 - (sizeof lf_hdr->encaps_pkt_len + ipv4_total_length0) % 16) % 16;
		RTE_ASSERT(encaps_trl_len < UINT16_MAX - encaps_hdr_len);

		if (unlikely(encaps_hdr_len + encaps_trl_len > UINT16_MAX - ipv4_total_length0)) {
			// #if LOG_PACKETS
			printf("[%d] Not yet implemented: LF packet too big to encapsualte.\n", lcore_id);
			// #endif
			return -1;
		}

		rte_be32_t ipv4_hdr_src_addr0 = ipv4_hdr0->src_addr;
		rte_be32_t ipv4_hdr_dst_addr0 = ipv4_hdr0->dst_addr;
		rte_be64_t src_ia = config.isd_as;

		ipv4_hdr0->hdr_checksum = 0;
		ipv4_hdr0->src_addr = 0;
		ipv4_hdr0->dst_addr = 0;

		char *p = rte_pktmbuf_prepend(m, encaps_hdr_len);
		RTE_ASSERT(p != NULL);

		RTE_ASSERT(sizeof *ether_hdr0 <= encaps_hdr_len);
		struct rte_ether_hdr *ether_hdr1 =
			rte_memcpy((char *)ether_hdr0 - encaps_hdr_len, ether_hdr0, sizeof *ether_hdr0);

		RTE_ASSERT(p == (char *)ether_hdr1);

		ipv4_hdr1 = (struct rte_ipv4_hdr *)(ether_hdr1 + 1);
		ipv4_hdr1->version_ihl = (IPV4_VERSION << 4) | (sizeof *ipv4_hdr1) / RTE_IPV4_IHL_MULTIPLIER;
		ipv4_hdr1->type_of_service = 0;
		ipv4_hdr1->total_length = rte_cpu_to_be_16(encaps_hdr_len + ipv4_total_length0);
		ipv4_hdr1->packet_id = 0;
		ipv4_hdr1->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
		ipv4_hdr1->time_to_live = IP_TTL_DEFAULT;
		ipv4_hdr1->next_proto_id = IP_PROTO_ID_UDP;
		ipv4_hdr1->hdr_checksum = 0;
		ipv4_hdr1->src_addr = ipv4_hdr_src_addr0;
		ipv4_hdr1->dst_addr = ipv4_hdr_dst_addr0;

		udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr1 + 1);
		udp_hdr->src_port = rte_cpu_to_be_16(LF_DEFAULT_PORT + lcore_id);
		udp_hdr->dst_port = rte_cpu_to_be_16(LF_DEFAULT_PORT + lcore_id);
		udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof *udp_hdr + sizeof *lf_hdr + ipv4_total_length0);
		udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr1, /* ol_flags: */ 0);

		lf_hdr = (struct lf_hdr *)(udp_hdr + 1);
		lf_hdr->lf_pkt_type = 0;
		lf_hdr->reserved[0] = 0;
		lf_hdr->reserved[1] = 0;
		lf_hdr->reserved[2] = 0;
		lf_hdr->src_ia = src_ia;
		lf_hdr->encaps_pkt_len = rte_cpu_to_be_16(ipv4_total_length0);

		if (encaps_trl_len != 0) {
			p = rte_pktmbuf_append(m, encaps_trl_len);
			RTE_ASSERT(p == (char *)(lf_hdr + 1) + ipv4_total_length0);
			(void)memset(p, 0, encaps_trl_len);
		}
		struct timeval tv;
		int r = gettimeofday(&tv, NULL);
		if (unlikely(r != 0)) {
			RTE_ASSERT(r == -1);
			// #if LOG_PACKETS
			printf("[%d] Syscall gettimeofday failed.\n", lcore_id);
			// #endif
			return -1;
		}
		RTE_ASSERT((INT64_MIN <= tv.tv_sec) && (tv.tv_sec <= INT64_MAX));
		int64_t t_now = tv.tv_sec;
		struct key_dictionary *d = key_dictionaries[lcore_id];
		key_dictionary_find(d, src_ia);
		struct key_store_node *n = d->value;
		if (n == NULL) {
			// #if LOG_PACKETS
			printf("[%d] Key store lookup failed.\n", lcore_id);
			// #endif
			return -1;
		}
		struct delegation_secret *ds = get_delegation_secret(n, t_now);
		if (ds == NULL) {
			// #if LOG_PACKETS
			printf("[%d] Delegation secret lookup failed.\n", lcore_id);
			// #endif
			return -1;
		}
#if LOG_PACKETS
		printf("[%d] DRKey for %0lx at %ld: {\n", lcore_id, src_ia, t_now);
		dump_hex(lcore_id, ds->key, 16);
		printf("[%d] }\n", lcore_id);
#endif
		compute_lf_chksum(lcore_id,
			/* drkey: */ ds->key,
			/* src_addr: */ backend_public_addr(ipv4_hdr_src_addr0),
			/* dst_addr: */ ipv4_hdr_dst_addr0,
			/* data: */ &lf_hdr->encaps_pkt_len,
			/* data_len: */ sizeof lf_hdr->encaps_pkt_len + ipv4_total_length0 + encaps_trl_len,
			/* chksum: */ lf_hdr->encaps_pkt_chksum,
			/* rkey_buf: */ roundkey[lcore_id],
			/* addr_buf: */ key_hosts_addrs[lcore_id]);
		if (encaps_trl_len != 0) {
			int r = rte_pktmbuf_trim(m, encaps_trl_len);
			RTE_ASSERT(r == 0);
		}

		m->l2_len = sizeof *ether_hdr1;
		m->l3_len = sizeof *ipv4_hdr1;
		m->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
	}

	swap_eth_addrs(m);

#if LOG_PACKETS
	printf("[%d] Forwarding outgoing packet:\n", lcore_id);
	dump_hex(lcore_id, rte_pktmbuf_mtod(m, char *), m->pkt_len);
#endif
	uint16_t n = rte_eth_tx_buffer(
		lvars->tx_bypass_port_id, lvars->tx_bypass_queue_id, lvars->tx_bypass_buffer, m);
	(void)n;
#if LOG_PACKETS
	if (n > 0) {
		printf("[%d] Flushed packets to TX port: %d\n", lcore_id, n);
	}
#endif

	return 0;
}

static void scionfwd_simple_forward(
	struct rte_mbuf *m, const unsigned lcore_id, struct lcore_values *lvars, int16_t state) {
#if SIMPLE_FORWARD
	swap_eth_addrs(m);

	#if LOG_PACKETS
	printf("[%d] Forwarding outgoing packet:\n", lcore_id);
	dump_hex(lcore_id, rte_pktmbuf_mtod(m, char *), m->pkt_len);
	#endif
	uint16_t n = rte_eth_tx_buffer(
		lvars->tx_bypass_port_id, lvars->tx_bypass_queue_id, lvars->tx_bypass_buffer, m);
	(void)n;
	#if LOG_PACKETS
	if (n > 0) {
		printf("[%d] Flushed packets to TX port: %d\n", lcore_id, n);
	}
	#endif
	return;
#endif

#if CHECK_PACKET_STRUCTURE
	if (unlikely(m->data_len != m->pkt_len)) {
		// #if LOG_PACKETS
		printf("[%d] Not yet implemented: buffer with multiple segments received.\n", lcore_id);
		// #endif
		goto drop_pkt;
	}
#endif

	struct rte_ether_hdr *ether_hdr0;
#if CHECK_PACKET_STRUCTURE
	if (unlikely(sizeof *ether_hdr0 > m->data_len)) {
		// #if LOG_PACKETS
		printf("[%d] Unsupported packet: Ethernet header exceeds first buffer segment.\n", lcore_id);
		// #endif
		goto drop_pkt;
	}
#endif
	ether_hdr0 = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (unlikely(ether_hdr0->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
		// #if LOG_PACKETS
		printf("[%d] Unsupported packet type: must be IPv4.\n", lcore_id);
		// #endif
		goto drop_pkt;
	}

	struct rte_ipv4_hdr *ipv4_hdr0;
#if CHECK_PACKET_STRUCTURE
	if (unlikely(sizeof *ipv4_hdr0 > m->data_len - sizeof *ether_hdr0)) {
		// #if LOG_PACKETS
		printf("[%d] Unsupported packet: IP header exceeds first buffer segment.\n", lcore_id);
		// #endif
		goto drop_pkt;
	}
#endif
	ipv4_hdr0 = (struct rte_ipv4_hdr *)(ether_hdr0 + 1);

	int r;
#if UNIDIRECTIONAL_SETUP
	(void)is_backend;
	(void)handle_outbound_pkt;
	r = handle_inbound_pkt(m, ether_hdr0, ipv4_hdr0, lcore_id, lvars, state);
#else
	if (is_backend(ipv4_hdr0->dst_addr)) {
		r = handle_inbound_pkt(m, ether_hdr0, ipv4_hdr0, lcore_id, lvars, state);
	} else if (is_backend(ipv4_hdr0->src_addr)) {
		r = handle_outbound_pkt(m, ether_hdr0, ipv4_hdr0, lcore_id, lvars);
	} else {
		goto drop_pkt;
	}
#endif
	if (r != 0) {
		RTE_ASSERT(r == -1);
		goto drop_pkt;
	}

	return;

drop_pkt:
#if LOG_PACKETS
	printf("[%d] Dropping packet.\n", lcore_id);
#endif
	rte_pktmbuf_free(m);
}

static void scionfwd_main_loop(void) {
	struct lcore_values *lvars;
	int16_t state;

	uint64_t last_dos_slice_tsc, prev_tsc, diff_tsc, cur_tsc;

	struct rte_mbuf *pkts_burst[MAX_PKT_BURST], *m;
	uint16_t i, n;

	const unsigned lcore_id = rte_lcore_id();

	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	last_dos_slice_tsc = rte_rdtsc();
	prev_tsc = 0;

#if ENABLE_MEASUREMENTS
	struct measurements *msmts = &measurements[lcore_id];
#endif

	lvars = &core_vars[lcore_id];

	if (lvars->rx_port_id == RTE_MAX_ETHPORTS) {
		return;
	}

	key_hosts_addrs[lcore_id] = rte_malloc(NULL, 32, 16);
	RTE_ASSERT(key_hosts_addrs[lcore_id]);

	roundkey[lcore_id] = rte_malloc(NULL, 10 * 16, 16);
	RTE_ASSERT(roundkey[lcore_id]);

	// zeroing is not required for CMAC(), but using output also
	// as 0 array for padding
	computed_cmac[lcore_id] = rte_malloc(NULL, 16, RTE_CACHE_LINE_SIZE);
	RTE_ASSERT(computed_cmac[lcore_id]);

#if !(defined __x86_64__ && __x86_64__)
	cipher_ctx[lcore_id] = EVP_CIPHER_CTX_new();
	RTE_ASSERT(cipher_ctx[lcore_id]);
#endif

	state = !rte_atomic16_read(&dos_state);

	while (!force_quit) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		// TX burst queue drain
		if (unlikely(diff_tsc > drain_tsc)) {
			prev_tsc = cur_tsc;
#if ENABLE_MEASUREMENTS
			msmts->tx_drain_start = rte_rdtsc();
#endif
			n = rte_eth_tx_buffer_flush(
				lvars->tx_bypass_port_id, lvars->tx_bypass_queue_id, lvars->tx_bypass_buffer);
#if LOG_PACKETS
			if (n > 0) {
				printf("[%d] Flushed packets to TX port: %d\n", lcore_id, n);
			}
#endif
			n = rte_eth_tx_buffer_flush(
				lvars->tx_firewall_port_id, lvars->tx_firewall_queue_id, lvars->tx_firewall_buffer);
#if LOG_PACKETS
			if (n > 0) {
				printf("[%d] Flushed packets to TX port: %d\n", lcore_id, n);
			}
#endif
#if ENABLE_MEASUREMENTS
			msmts->tx_drain_cnt++;
			msmts->tx_drain_sum += rte_rdtsc() - msmts->tx_drain_start;
#endif
		}

#if ENABLE_MEASUREMENTS
		msmts->rx_drain_start = rte_rdtsc();
#endif

		n = rte_eth_rx_burst(lvars->rx_port_id, lvars->rx_queue_id, pkts_burst, MAX_PKT_BURST);

#if ENABLE_MEASUREMENTS
		msmts->rx_drain_cnt = rte_rdtsc();
		msmts->rx_drain_sum += rte_rdtsc() - msmts->rx_drain_start;
#endif

		// prefetch all RX packets
		for (i = 0; i < n; i++) {
			m = pkts_burst[i];

#if LOG_PACKETS
			printf("[%d] Fetching packet: %d/%d\n", lcore_id, i, n);
			dump_hex(lcore_id, rte_pktmbuf_mtod(m, char *), m->pkt_len);
#endif

			rte_prefetch0(rte_pktmbuf_mtod(m, void *));

#if ENABLE_MEASUREMENTS
			msmts->dup_start = rte_rdtsc();
#endif

			// Check the rate-limiter state roughly every 100 microseconds and set own
			// state to opposite of the rate-limiter. This has to be done before each
			// packet processing, to make sure that we are always in the correct
			// state.
			if (cur_tsc - last_dos_slice_tsc > dos_slice_period) {
				state = !rte_atomic16_read(&dos_state);
				last_dos_slice_tsc = cur_tsc;
			}

			scionfwd_simple_forward(m, lcore_id, lvars, state);

#if ENABLE_MEASUREMENTS
			msmts->dup_cnt++;
			msmts->dup_sum += rte_rdtsc() - msmts->dup_start;
#endif
		}
	}
}

/*
 * called by metrics exporter once at start-up
 * inititalizes memory structures and exports all system information and
 * the configuration
 * communicates via IPC with the Go metrics exporter
 */
static void export_set_up_metrics(void) {
	register int s, socket_len;
	struct sockaddr_un saun;
	char buffer[256];

	uint8_t port_id;
	struct port_values *port;
	struct rte_ether_addr mac_addr;
	int port_socket_id;

	saun.sun_family = AF_UNIX;
	strcpy(saun.sun_path, ADDRESS);

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		rte_exit(EXIT_FAILURE, "Metrics core could not get a UNIX socket\n");
	}

	socket_len = sizeof saun.sun_family + strlen(saun.sun_path);
	if (connect(s, &saun, socket_len) < 0) {
		printf("Metrics could not connect to socket\n");
	}

	snprintf(buffer, sizeof buffer,
		"set_up_sys_stats;%" PRIu64 ";%d;%" PRIu64 ";%" PRIu64 ";%d;%" PRIu32 ";%" PRIu8 ";%" PRIu8
		";%" PRIu8 ";%" PRIu8 ";%" PRIu8 ";%" PRIu32 ";%" PRIu32 ";%" PRIu64 ";fin\n",
		slice_timer_period_seconds, BLOOM_FILTERS, NUM_BLOOM_ENTRIES, BLOOM_ERROR_RATE, delta_us, 0,
		nb_ports, nb_rx_ports, nb_tx_ports, nb_tx_bypass_ports, nb_tx_firewall_ports, nb_cores,
		nb_slave_cores, receive_limit);
	send(s, buffer, strlen(buffer), 0);

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (is_active_port[port_id] == false) {
			continue;
		}

		port = &port_vars[port_id];
		port_socket_id = rte_eth_dev_socket_id(port_id);
		mac_addr = port->eth_addr;

		snprintf(buffer, sizeof buffer,
			"set_up_port_stats;%d;%02X:%02X:%02X:%02X:%02X:%02X;%d;%s;%x;%u;%u;%" PRIu64 ";%" PRIu32
			";%u;%" PRIu32 ";%" PRIu32 ";%" PRIu32 ";%" PRIu32 ";%" PRIu32 ";%" PRIu64 ";%" PRIu64
			";%" PRIu64 ";%" PRIu64 ";%" PRIu16 ";%" PRIu8 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";fin\n",
			port_id, mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
			mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5], port_socket_id,
			port->dev_info.driver_name, port->dev_info.if_index, port->dev_info.min_mtu,
			port->dev_info.max_mtu, (uint64_t)(port->dev_info.dev_flags), port->dev_info.min_rx_bufsize,
			port->dev_info.max_rx_pktlen, port->dev_info.max_rx_queues, port->dev_info.max_tx_queues,
			port->dev_info.max_mac_addrs, port->dev_info.max_vfs, port->dev_info.max_vmdq_pools,
			port->dev_info.rx_offload_capa, port->dev_info.tx_offload_capa,
			port->dev_info.rx_queue_offload_capa, port->dev_info.tx_queue_offload_capa,
			port->dev_info.reta_size, port->dev_info.hash_key_size, port->dev_info.flow_type_rss_offloads,
			(uint64_t)(port->dev_info.speed_capa), (uint64_t)(port->dev_info.dev_capa));
		send(s, buffer, strlen(buffer), 0);
	}

	close(s);
}

/* main loop of the metrics exporter
 * call the initial metrics export
 * communicates with Go exporter via IPC
 * to avoid holding on to the socket indefinitely and loosing it due to unforeseen events,
 * we reconnect every loop iteration and disconnect at the end of it.
 * This enables recovery at the cost of missing data-points, which is ok for stats collection over
 * long time periods
 */
static void metrics_main_loop(void) {
	printf("METRICS HAS STARTED\n");

	register int s, socket_len;
	int ret;
	struct sockaddr_un saun;
	char buffer[256];

	uint64_t last_slice_tsc = rte_rdtsc();
	uint64_t current_tsc;

	// lots of system-wide accumulators
	uint64_t total_rx_counter = 0;
	uint64_t total_tx_bypass_counter = 0;
	uint64_t total_tx_firewall_counter = 0;
	uint64_t total_key_mismatch_counter = 0;
	uint64_t total_secX_fail_counter = 0;
	uint64_t total_bloom_filter_hit_counter = 0;
	uint64_t total_bloom_filter_miss_counter = 0;
	uint64_t total_as_rate_limited_counter = 0;
	uint64_t total_rate_limited_counter = 0;

	uint64_t rx_counter = 0;
	uint64_t tx_bypass_counter = 0;
	uint64_t tx_firewall_counter = 0;
	uint64_t key_mismatch_counter = 0;
	uint64_t secX_fail_counter = 0;
	uint64_t bloom_filter_hit_counter = 0;
	uint64_t bloom_filter_miss_counter = 0;
	uint64_t as_rate_limited_counter = 0;
	uint64_t rate_limited_counter = 0;

	export_set_up_metrics();

	saun.sun_family = AF_UNIX;
	strcpy(saun.sun_path, ADDRESS);

	/* main loop */
	while (!force_quit) {
		current_tsc = rte_rdtsc();

		// perform stats export according to slice timer period (default every 5 seconds)
		if (unlikely(current_tsc - last_slice_tsc > slice_timer_period)) {
			// update timings (hz may change due to turbo feature of cpu (Jonas: It does not really change
			// though?))
			slice_timer_period = slice_timer_period_seconds * rte_get_timer_hz();
			last_slice_tsc = current_tsc;

			// Acquire socket
			if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
				// rte_exit(EXIT_FAILURE, "Metrics core could not get a UNIX socket\n");
			}

			// connect to socket
			socket_len = sizeof saun.sun_family + strlen(saun.sun_path);
			if (connect(s, &saun, socket_len) < 0) {
				// printf("metrics could not connect to socket\n");
			}

			// for each active port get hardware stats
			for (int port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
				if (is_active_port[port_id] == false) {
					continue;
				}
				struct rte_eth_stats rte_stats;
				ret = rte_eth_stats_get(port_id, &rte_stats); // get HW stats
				if (ret < 0) {
					continue;
				}
				rte_eth_stats_reset(port_id); // reset HW stats

				// send HW stats
				snprintf(buffer, sizeof buffer,
					"port_stats;%d;%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64
					";%" PRIu64 ";%" PRIu64 ";fin\n",
					port_id, rte_stats.ipackets, rte_stats.opackets, rte_stats.ibytes, rte_stats.obytes,
					rte_stats.imissed, rte_stats.ierrors, rte_stats.oerrors, rte_stats.rx_nombuf);
				send(s, buffer, strlen(buffer), 0);
			}

			// for each lcore accumulate stats, reset intivdulas stats and send aggregate
			for (int i = 0; i < RTE_MAX_LCORE; i++) {
				if (is_slave_core[i] == false) {
					continue;
				}

				// collect lcore stats
				struct core_stats *lstats = &(core_vars[i].stats);
				rx_counter = lstats->rx_counter;
				tx_bypass_counter = lstats->tx_bypass_counter;
				tx_firewall_counter = lstats->tx_firewall_counter;
				key_mismatch_counter = lstats->key_mismatch_counter;
				secX_fail_counter = lstats->secX_fail_counter;
				bloom_filter_hit_counter = lstats->bloom_filter_hit_counter;
				bloom_filter_miss_counter = lstats->bloom_filter_miss_counter;
				as_rate_limited_counter = lstats->as_rate_limited;
				rate_limited_counter = lstats->rate_limited;

				// reset lcore stats
				lstats->rx_counter = 0;
				lstats->tx_bypass_counter = 0;
				lstats->tx_firewall_counter = 0;
				lstats->key_mismatch_counter = 0;
				lstats->secX_fail_counter = 0;
				lstats->bloom_filter_hit_counter = 0;
				lstats->bloom_filter_miss_counter = 0;
				lstats->as_rate_limited = 0;
				lstats->rate_limited = 0;

				// accumulate system-wide stats
				total_rx_counter += rx_counter;
				total_tx_bypass_counter += tx_bypass_counter;
				total_tx_firewall_counter += tx_firewall_counter;
				total_key_mismatch_counter += key_mismatch_counter;
				total_secX_fail_counter += secX_fail_counter;
				total_bloom_filter_hit_counter += bloom_filter_hit_counter;
				total_bloom_filter_miss_counter += bloom_filter_miss_counter;
				total_as_rate_limited_counter += as_rate_limited_counter;
				total_rate_limited_counter += rate_limited_counter;

				// send individual lcore stats
				snprintf(buffer, sizeof buffer,
					"core_stats;%d;%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64
					";%" PRIu64 ";fin\n",
					i, rx_counter, tx_bypass_counter, tx_firewall_counter, key_mismatch_counter,
					secX_fail_counter, bloom_filter_hit_counter, bloom_filter_miss_counter);
				send(s, buffer, strlen(buffer), 0);
			}

			// send system-wide aggregate
			snprintf(buffer, sizeof buffer,
				"core_stats;%d;%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64
				";%" PRIu64 ";fin\n",
				-1, total_rx_counter, total_tx_bypass_counter, total_tx_firewall_counter,
				total_key_mismatch_counter, total_secX_fail_counter, total_bloom_filter_hit_counter,
				total_bloom_filter_miss_counter);
			send(s, buffer, strlen(buffer), 0);

			// reset system-wide counters
			total_rx_counter = 0;
			total_tx_bypass_counter = 0;
			total_tx_firewall_counter = 0;
			total_key_mismatch_counter = 0;
			total_secX_fail_counter = 0;
			total_bloom_filter_hit_counter = 0;
			total_bloom_filter_miss_counter = 0;
			total_as_rate_limited_counter = 0;
			total_rate_limited_counter = 0;

			// collect for each AS the key-store information
			struct key_dictionary *d = key_dictionaries[key_manager_core_id];

			for (size_t i = 0; i < d->size; i++) {
				if (d->table[i] != NULL) {
					struct key_dictionary_node *n = d->table[i];
					while (n != NULL) {
						struct delegation_secret *ds =
							&n->value->key_store->delegation_secrets[n->value->key_index];
						snprintf(buffer, sizeof buffer,
							"key_stats;%" PRIu64 ";%" PRIi64 ";%" PRIi64 ";%" PRIi64 ";%" PRIi64 ";fin\n", n->key,
							ds->validity_not_before, ds->validity_not_after, min_key_validity,
							max_key_validity_extension);
						send(s, buffer, strlen(buffer), 0);
						n = n->next;
					}
				}
			}
			close(s);

#if ENABLE_MEASUREMENTS

			/* cylce analysis code *
			 * take average across all cores for each pipeline step and print
			 * contains a lot of boilerplate code
			 */

			uint64_t dup_avg = 0;
			uint64_t header_avg = 0;
			uint64_t secX_avg = 0;
			uint64_t secX_zero_avg = 0;
			uint64_t secX_deriv_avg = 0;
			uint64_t secX_cmac_avg = 0;
			uint64_t bloom_add_avg = 0;
			uint64_t bloom_free_avg = 0;
			uint64_t pktcopy_avg = 0;
			uint64_t tx_enqueue_avg = 0;
			uint64_t tx_drain_avg = 0;
			uint64_t rx_drain_avg = 0;
			uint64_t rate_limit_avg = 0;
			uint64_t active_dup_cores = 0;

			for (int i = 0; i < RTE_MAX_LCORE; i++) {
				if (measurements[i].dup_cnt) {
					// packet counter
					if (measurements[i].dup_cnt) {
						dup_avg += (measurements[i].dup_sum / measurements[i].dup_cnt);
						active_dup_cores++;
					}
					measurements[i].dup_sum = 0;
					measurements[i].dup_cnt = 0;

					// header counter
					if (measurements[i].header_cnt) {
						header_avg += (measurements[i].header_sum / measurements[i].header_cnt);
					}
					measurements[i].header_sum = 0;
					measurements[i].header_cnt = 0;

					// rate limit counter
					if (measurements[i].rate_limit_cnt) {
						rate_limit_avg += (measurements[i].rate_limit_sum / measurements[i].rate_limit_cnt);
					}
					measurements[i].rate_limit_sum = 0;
					measurements[i].rate_limit_cnt = 0;

					// secX counter
					if (measurements[i].secX_cnt) {
						secX_avg += (measurements[i].secX_sum / measurements[i].secX_cnt);
					}
					measurements[i].secX_sum = 0;
					measurements[i].secX_cnt = 0;

					// secX zero counter
					if (measurements[i].secX_zero_cnt) {
						secX_zero_avg += (measurements[i].secX_zero_sum / measurements[i].secX_zero_cnt);
					}
					measurements[i].secX_zero_sum = 0;
					measurements[i].secX_zero_cnt = 0;

					// secX deriv counter
					if (measurements[i].secX_deriv_cnt) {
						secX_deriv_avg += (measurements[i].secX_deriv_sum / measurements[i].secX_deriv_cnt);
					}
					measurements[i].secX_deriv_sum = 0;
					measurements[i].secX_deriv_cnt = 0;

					// secX cmac counter
					if (measurements[i].secX_cmac_cnt) {
						secX_cmac_avg += (measurements[i].secX_cmac_sum / measurements[i].secX_cmac_cnt);
					}
					measurements[i].secX_cmac_sum = 0;
					measurements[i].secX_cmac_cnt = 0;

					// bloom filter add counter
					if (measurements[i].bloom_add_cnt) {
						bloom_add_avg += (measurements[i].bloom_add_sum / measurements[i].bloom_add_cnt);
					}
					measurements[i].bloom_add_sum = 0;
					measurements[i].bloom_add_cnt = 0;

					// bloom filter reset
					if (measurements[i].bloom_free_cnt) {
						bloom_free_avg += (measurements[i].bloom_free_sum / measurements[i].bloom_free_cnt);
					}
					measurements[i].bloom_free_sum = 0;
					measurements[i].bloom_free_cnt = 0;

					// packet copy counter
					if (measurements[i].pktcopy_cnt) {
						pktcopy_avg += (measurements[i].pktcopy_sum / measurements[i].pktcopy_cnt);
					}
					measurements[i].pktcopy_sum = 0;
					measurements[i].pktcopy_cnt = 0;

					// enqueued counter
					if (measurements[i].tx_enqueue_cnt) {
						tx_enqueue_avg += (measurements[i].tx_enqueue_sum / measurements[i].tx_enqueue_cnt);
					}
					measurements[i].tx_enqueue_sum = 0;
					measurements[i].tx_enqueue_cnt = 0;

					// tx drain counter
					if (measurements[i].tx_drain_cnt) {
						tx_drain_avg += (measurements[i].tx_drain_sum / measurements[i].tx_drain_cnt);
					}
					measurements[i].tx_drain_sum = 0;
					measurements[i].tx_drain_cnt = 0;

					// rx drain counter
					if (measurements[i].rx_drain_cnt) {
						rx_drain_avg += (measurements[i].rx_drain_sum / measurements[i].rx_drain_cnt);
					}
					measurements[i].rx_drain_sum = 0;
					measurements[i].rx_drain_cnt = 0;
				}
			}

			printf("Cycles per second: %" PRIu64 "\n", tsc_hz);

			if (dup_avg)
				dup_avg /= active_dup_cores;
			printf("Total average duplicate detection processing: %" PRIu64 "\n", dup_avg);

			if (rx_drain_avg)
				rx_drain_avg /= active_dup_cores;
			printf("| Average rx drain processing: %" PRIu64 "\n", rx_drain_avg);

			if (header_avg)
				header_avg /= active_dup_cores;
			printf("| Average header processing: %" PRIu64 "\n", header_avg);

			if (rate_limit_avg)
				rate_limit_avg /= active_dup_cores;
			printf("| Average rate limit processing: %" PRIu64 "\n", rate_limit_avg);

			if (pktcopy_avg)
				pktcopy_avg /= active_dup_cores;
			printf("| Average packet copy processing: %" PRIu64 "\n", pktcopy_avg);

			if (secX_avg)
				secX_avg /= active_dup_cores;
			printf("| Average security extension processing: %" PRIu64 "\n", secX_avg);

			if (secX_zero_avg)
				secX_zero_avg /= active_dup_cores;
			printf("  | Average zeroing-out processing: %" PRIu64 "\n", secX_zero_avg);

			if (secX_deriv_avg)
				secX_deriv_avg /= active_dup_cores;
			printf("  | Average key derivation processing: %" PRIu64 "\n", secX_deriv_avg);

			if (secX_cmac_avg)
				secX_cmac_avg /= active_dup_cores;
			printf("  | Average CMAC computation processing: %" PRIu64 "\n", secX_cmac_avg);

			if (bloom_free_avg)
				bloom_free_avg /= active_dup_cores;
			printf("| Average bloom free-init processing: %" PRIu64 "\n", bloom_free_avg);

			if (bloom_add_avg)
				bloom_add_avg /= active_dup_cores;
			printf("| Average bloom adding processing: %" PRIu64 "\n", bloom_add_avg);

			if (tx_enqueue_avg)
				tx_enqueue_avg /= active_dup_cores;
			printf("| Average tx enqueue processing: %" PRIu64 "\n", tx_enqueue_avg);

			if (tx_drain_avg)
				tx_drain_avg /= active_dup_cores;
			printf("| Average tx drain processing: %" PRIu64 "\n", tx_drain_avg);

			printf("\n");
#endif
		}
	}
}

/*
 * Key management. For background information on the general design, see
 * https://github.com/scionproto/scion/blob/master/doc/cryptography/DRKeyInfra.md
 */

static void add_key_store_nodes(uint64_t src_ia) {
	struct key_store *key_store = malloc(sizeof *key_store);
	if (key_store == NULL) {
		rte_exit(EXIT_FAILURE, "Allocation of key store failed.\n");
	}
	memset(key_store, 0, sizeof *key_store);
	for (size_t core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
		if (!is_in_use[core_id]) {
			continue;
		}
		struct key_store_node *n = malloc(sizeof *n);
		if (n == NULL) {
			rte_exit(EXIT_FAILURE, "Allocation of key store node failed.\n");
		}
		n->key_index = 0;
		n->key_store = key_store;
		int r = key_dictionary_add(key_dictionaries[core_id], src_ia, n);
		if (r == -1) {
			rte_exit(EXIT_FAILURE, "Registration of key store node failed.\n");
		}
		RTE_ASSERT(r == 0);
	}
}

static void init_key_manager(void) {
	for (size_t core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
		RTE_ASSERT(core_id < sizeof is_in_use / sizeof is_in_use[0]);
		if (!is_in_use[core_id]) {
			continue;
		}
		struct key_dictionary *d = key_dictionary_new(DEFAULT_KEY_DICTIONARY_SIZE);
		if (d == NULL) {
			rte_exit(EXIT_FAILURE, "Allocation of key dictionary failed.\n");
		}
		RTE_ASSERT(core_id < sizeof key_dictionaries / sizeof key_dictionaries[0]);
		key_dictionaries[core_id] = d;
	}

	for (struct lf_config_peer *p = config.peers; p != NULL; p = p->next) {
		add_key_store_nodes(p->isd_as);
	}
	if (config.backends != NULL) {
		add_key_store_nodes(config.isd_as);
	}

	min_key_validity = DEFAULT_KEY_VALIDITY;
}

#if LOG_DELEGATION_SECRETS
static void print_delegation_secret(
	uint64_t src_ia, uint64_t dst_ia, int64_t val_time, struct delegation_secret *ds) {
	struct tm *gmt;
	printf("DS key (srcIA = %lx, dstIA = %lx) ", src_ia, dst_ia);
	gmt = gmtime((time_t *)&val_time);
	if (gmt != NULL) {
		printf("at %04d-%02d-%02d'T'%02d:%02d:%02d'Z' = ", 1900 + gmt->tm_year, 1 + gmt->tm_mon,
			gmt->tm_mday, gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
	} else {
		printf("= ");
	}
	for (size_t i = 0; i < sizeof ds->key; i++) {
		printf("%02x", ds->key[i]);
	}
	printf(", epoch = [");
	gmt = gmtime((time_t *)&ds->validity_not_before);
	if (gmt != NULL) {
		printf("%04d-%02d-%02d'T'%02d:%02d:%02d'Z'", 1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
			gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
	}
	printf(", ");
	gmt = gmtime((time_t *)&ds->validity_not_after);
	if (gmt != NULL) {
		printf("%04d-%02d-%02d'T'%02d:%02d:%02d'Z'", 1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
			gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
	}
	printf("]\n");
}
#endif

static int fetch_delegation_secret(
	uint64_t src_ia, uint64_t dst_ia, int64_t val_time, struct delegation_secret *ds) {
	int r;
#if ENABLE_KEY_MANAGEMENT
	char sciondAddr[] = "127.0.0.1:30255";
	memset(ds, 0, sizeof *ds);
	RTE_ASSERT(sizeof ds->validity_not_before == sizeof(GoInt64));
	RTE_ASSERT(sizeof ds->validity_not_after == sizeof(GoInt64));
	r = GetDelegationSecret(sciondAddr, src_ia, dst_ia, val_time, (GoInt64 *)&ds->validity_not_before,
		(GoInt64 *)&ds->validity_not_after, ds->key);
	if (r != 0) {
		RTE_ASSERT(r == -1);
		usleep(500 * 1000);
	}
#else
	(void)src_ia;
	(void)dst_ia;
	int64_t m = val_time % DEFAULT_KEY_VALIDITY;
	if (m < 0) {
		m += DEFAULT_KEY_VALIDITY;
	}
	if (INT64_MIN + m <= val_time) {
		ds->validity_not_before = val_time - m;
	} else {
		ds->validity_not_before = INT64_MIN;
	}
	if (ds->validity_not_before <= INT64_MAX - DEFAULT_KEY_VALIDITY) {
		ds->validity_not_after = ds->validity_not_before + DEFAULT_KEY_VALIDITY;
	} else {
		ds->validity_not_after = INT64_MAX;
	}
	memset(ds->key, 0, sizeof ds->key);
	r = 0;
#endif
#if LOG_DELEGATION_SECRETS
	print_delegation_secret(src_ia, dst_ia, val_time, ds);
#endif
	return r;
}

static void fetch_delegation_secrets(
	struct key_store_node *n, uint64_t src_ia, uint64_t dst_ia, int64_t val_time) {
	struct key_store *s = n->key_store;
	RTE_ASSERT(sizeof s->delegation_secrets / sizeof s->delegation_secrets[0] == 3);
	struct delegation_secret ds;
	int r = fetch_delegation_secret(src_ia, dst_ia, val_time, &ds);
	if (r == 0) {
		RTE_ASSERT(ds.validity_not_before < ds.validity_not_after);
		s->delegation_secrets[0] = ds;
		int64_t key_validity = ds.validity_not_after - ds.validity_not_before;
		if (key_validity < min_key_validity) {
			min_key_validity = key_validity;
		}
		if (ds.validity_not_after != INT64_MAX) {
			struct delegation_secret next;
			r = fetch_delegation_secret(src_ia, dst_ia, ds.validity_not_after + 1, &next);
			if (r == 0) {
				RTE_ASSERT(next.validity_not_before < next.validity_not_after);
				s->delegation_secrets[1] = next;
				key_validity = next.validity_not_after - next.validity_not_before;
				if (key_validity < min_key_validity) {
					min_key_validity = key_validity;
				}
			}
		}
		if (ds.validity_not_before != INT64_MIN) {
			struct delegation_secret prev;
			r = fetch_delegation_secret(src_ia, dst_ia, ds.validity_not_before - 1, &prev);
			if (r == 0) {
				// RTE_ASSERT(prev.validity_not_before < prev.validity_not_after);
				s->delegation_secrets[2] = prev;
				key_validity = prev.validity_not_after - prev.validity_not_before;
				if (key_validity < min_key_validity) {
					min_key_validity = key_validity;
				}
			}
		}
	}
}

static void check_adjacent_delegation_secrets(
	struct key_store_node *n, uint64_t src_ia, uint64_t dst_ia) {
	struct key_store *s = n->key_store;
	RTE_ASSERT(sizeof s->delegation_secrets / sizeof s->delegation_secrets[0] == 3);
	struct delegation_secret *ds = &s->delegation_secrets[n->key_index];
	RTE_ASSERT(ds->validity_not_before < ds->validity_not_after);
	if (ds->validity_not_after != INT64_MAX) {
		size_t next_key_index = NEXT_KEY_INDEX(n->key_index);
		struct delegation_secret *next_ds = &s->delegation_secrets[next_key_index];
		if ((next_ds->validity_not_before >= next_ds->validity_not_after)
				|| (ds->validity_not_after >= next_ds->validity_not_after))
		{
			struct delegation_secret next;
			int r = fetch_delegation_secret(src_ia, dst_ia, ds->validity_not_after + 1, &next);
			if (r == 0) {
				RTE_ASSERT(next.validity_not_before < next.validity_not_after);
				*next_ds = next;
				int64_t key_validity = next.validity_not_after - next.validity_not_before;
				if (key_validity < min_key_validity) {
					min_key_validity = key_validity;
				}
			}
		}
	}
	if (ds->validity_not_before != INT64_MIN) {
		size_t prev_key_index = PREV_KEY_INDEX(n->key_index);
		struct delegation_secret *prev_ds = &s->delegation_secrets[prev_key_index];
		if ((prev_ds->validity_not_before >= prev_ds->validity_not_after)
				|| (ds->validity_not_before <= prev_ds->validity_not_before))
		{
			struct delegation_secret prev;
			int r = fetch_delegation_secret(src_ia, dst_ia, ds->validity_not_before - 1, &prev);
			if (r == 0) {
				// RTE_ASSERT(prev.validity_not_before < prev.validity_not_after);
				*prev_ds = prev;
				int64_t key_validity = prev.validity_not_after - prev.validity_not_before;
				if (key_validity < min_key_validity) {
					min_key_validity = key_validity;
				}
			}
		}
	}
}

static void key_manager_main_loop(void) {
	printf("KEY MANAGER HAS STARTED\n");
	RTE_ASSERT(key_manager_core_id < sizeof key_dictionaries / sizeof key_dictionaries[0]);
	struct key_dictionary *d = key_dictionaries[key_manager_core_id];
	RTE_ASSERT(d != NULL);
	RTE_ASSERT(d->table != NULL);
	int64_t i = 0;
	while (!force_quit) {
		if (i == 0) {
			struct timeval tv;
			int r = gettimeofday(&tv, NULL);
			if (r != 0) {
				RTE_ASSERT(r == -1);
				rte_exit(EXIT_FAILURE, "Syscall gettimeofday failed.\n");
			}
			RTE_ASSERT((INT64_MIN <= tv.tv_sec) && (tv.tv_sec <= INT64_MAX));
			int64_t t_now = tv.tv_sec;
			for (size_t j = 0; j < d->size; j++) {
				if (d->table[j] != NULL) {
					struct key_dictionary_node *n = d->table[j];
					while (n != NULL) {
						struct delegation_secret *ds = get_delegation_secret(n->value, t_now);
						if (ds == NULL) {
							fetch_delegation_secrets(n->value, n->key, config.isd_as, t_now);
						} else {
							check_adjacent_delegation_secrets(n->value, n->key, config.isd_as);
						}
						n = n->next;
					}
				}
			}
		}
		sleep(1);
		RTE_ASSERT(min_key_validity > 0);
		RTE_ASSERT(min_key_validity <= DEFAULT_KEY_VALIDITY);
		i = i < min_key_validity / 10 ? i + 1 : 0;
	}
}

/*
 * this function initialises the rate-limiter and defines the initial buckets.
 * As described in the "LightningFilter" thesis we use a modified version of token bucket
 *
 * The code contains some boilerplate because we have to calculate rate limits both system-wide
 * and per-AS, for SecX and normal SCION traffic. Moreover, to avoid data races, we calculate the
 * rate-limits for alternating even and odd states. Also we need to store the counters for the
 * previous slices both system-wide and per-AS.
 */
static void init_dos(void) {
	int initial_size = 32;
	dos_statistic *dos_stat;
	dos_counter *counter;

	// reserve counters (have to be atomic because they are shared among all lcores)
	rte_atomic64_t *reserve_all_even = malloc(sizeof *reserve_all_even);
	rte_atomic64_t *reserve_all_odd = malloc(sizeof *reserve_all_odd);

	// systemwide token pools initialized to zero for both states
	current_pool[0] = 0;
	current_pool[1] = 0;

	// for each core initialize:
	for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
		if (is_in_use[core_id] == false) {
			continue;
		}

		// set the previous slcie counter to zero
		previous_dos_stat[core_id].secX_dos_packet_count[0] = 0;
		previous_dos_stat[core_id].secX_dos_packet_count[1] = 0;
		previous_dos_stat[core_id].sc_dos_packet_count[0] = 0;
		previous_dos_stat[core_id].sc_dos_packet_count[1] = 0;

		// initialize the dictionaries
		dos_stat = &dos_stats[core_id];
		dictionary_flow *dict_odd = dic_new_flow(initial_size);
		dictionary_flow *dict_even = dic_new_flow(initial_size);

		// store the dictionaries
		dos_stat->dos_dictionary[ODD] = dict_odd;
		dos_stat->dos_dictionary[EVEN] = dict_even;

		// set pointers to the reserve
		dos_stat->reserve[ODD] = reserve_all_odd;
		dos_stat->reserve[EVEN] = reserve_all_even;

		// initialize previous dictionaries
		dict_odd = dic_new_flow(initial_size);
		dict_even = dic_new_flow(initial_size);

		// set previous dictionaries
		previous_dos_stat[core_id].dos_dictionary[ODD] = dict_odd;
		previous_dos_stat[core_id].dos_dictionary[EVEN] = dict_even;
	}

	// for each AS store the create and link the per-AS reserve and intialize the counters and refill
	// rates with the values read from the configuration file
	for (struct lf_config_peer *p = config.peers; p != NULL; p = p->next) {
		// create reserves for that AS shared among all lcores (atomic counter)
		rte_atomic64_t *reserve_as_odd = malloc(sizeof *reserve_as_odd);
		rte_atomic64_t *reserve_as_even = malloc(sizeof *reserve_as_even);

		// for each core do:
		for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
			if (is_in_use[core_id] == false) {
				continue;
			}

			dos_stat = &dos_stats[core_id];

			// create dos_counter for odd dictionary
			counter = malloc(sizeof *counter);
			counter->secX_counter = 0;
			counter->sc_counter = 0;
			counter->refill_rate = p->rate_limit;
			counter->reserve = reserve_as_odd; // pointer to reserve atomic
			dic_add_flow(dos_stat->dos_dictionary[ODD], p->isd_as, counter);

			// create dos_counter for even dictionary
			counter = malloc(sizeof *counter);
			counter->secX_counter = 0;
			counter->sc_counter = 0;
			counter->refill_rate = p->rate_limit;
			counter->reserve = reserve_as_even; // pointer to reserve atomic
			dic_add_flow(dos_stat->dos_dictionary[EVEN], p->isd_as, counter);

			// create dos_counter for PREVIOUS odd dictionary
			counter = malloc(sizeof *counter);
			counter->secX_counter = 0;
			counter->sc_counter = 0;
			counter->refill_rate = p->rate_limit;
			dic_add_flow(previous_dos_stat[core_id].dos_dictionary[ODD], p->isd_as, counter);

			// create dos_counter for PREVIOUS even dictionary
			counter = malloc(sizeof *counter);
			counter->secX_counter = 0;
			counter->sc_counter = 0;
			counter->refill_rate = p->rate_limit;
			dic_add_flow(previous_dos_stat[core_id].dos_dictionary[EVEN], p->isd_as, counter);
		}
	}
}

/*
 * this function recomputes the buckets each interval (100 microseconds)
 * As described in the "LighningFilter" thesis we use a modified version of token bucket
 * We perform three steps:
 * I) aggregate per core counters (tokens used)
 * 2) recompute token pool (pool_size + refill-rate - tokens-used)
 * 3) distribute newly available tokens among cores and reserve
 *
 * The code contains some boilerplate because we have to calculate rate limits both system-wide
 * and per-AS, for SecX and normal SCION traffic. Moreover, to avoid data races, we calculate the
 * rate-limits for alternating even and odd states. Also we need to store the counters for the
 * previous slices both system-wide and per-AS.
 */
static void dos_main_loop(void) {
	int16_t state;
	int64_t reserve_count;
	uint64_t last_dos_slice_tsc = rte_rdtsc();
	uint64_t current_tsc;

	struct dos_statistic core_dos_stat;
	struct dos_statistic dos_stat;
	struct dictionary_flow *dict;
	struct dictionary_flow *lcore_dict;

	printf("DOS HAS STARTED\n");

	dos_stat = dos_stats[rte_lcore_id()];
	dos_slice_period = rte_get_timer_hz() / 10000; // 100 micro-seconds
	state = EVEN; // initial rate-limiter state: EVEN -> initial processing core state: ODD

	/* main loop */
	while (!force_quit) {
		current_tsc = rte_rdtsc();
		// wait slightly longer to avoid data races with data-plane
		if (current_tsc - last_dos_slice_tsc > dos_slice_period + 10000) {
			dos_slice_period = (rte_get_timer_hz() / 10000) - 10000; // compensate for the extra cylces
			last_dos_slice_tsc = current_tsc;

			// go to oposide state (could be simply state != state)
			if (state == EVEN) {
				state = ODD;
			} else {
				state = EVEN;
			}
			// set new state in global state variable (this is the only thread that writes, all others are
			// read only)
			rte_atomic16_set(&dos_state, state);

			// reset aggregate variables
			int64_t secX_count = 0;
			int64_t sc_count = 0;
			int64_t used_secX = 0;
			int64_t used_sc = 0;
			int64_t used_secX_sum = 0;
			int64_t used_sc_sum = 0;
			int64_t refill_rate = config.system_limit; // global refill rate
			int64_t MAX_POOL_SIZE = refill_rate * MAX_POOL_SIZE_FACTOR;

			// aggregate over all lcores
			for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
				if (is_slave_core[core_id] == false) {
					continue;
				}
				core_dos_stat = dos_stats[core_id];

				// compute used secX tokens
				/* we allocated x tokens to a core
				 * if the core used less than x -> used = allocated - core counter value
				 * if the core used more than x -> used = allocated + core counter value (which must be
				 * negative)*/
				used_secX = core_dos_stat.secX_dos_packet_count[state];
				if (used_secX < 0) {
					used_secX_sum +=
						labs(used_secX) + previous_dos_stat[core_id].secX_dos_packet_count[state];
				} else {
					used_secX_sum += previous_dos_stat[core_id].secX_dos_packet_count[state] - used_secX;
				}

				// compute used normal SCION tokens
				used_sc = core_dos_stat.sc_dos_packet_count[state];
				if (used_sc < 0) {
					used_sc_sum += labs(used_sc) + previous_dos_stat[core_id].sc_dos_packet_count[state];
				} else {
					used_sc_sum += previous_dos_stat[core_id].sc_dos_packet_count[state] - used_sc;
				}
			}

			// refill the pool
			current_pool[state] += refill_rate;

			// take from the refilled pool
			secX_count = current_pool[state] - used_secX_sum;
			sc_count = current_pool[state] - used_secX_sum - used_sc_sum;

			// update the pool size, based on the tokens allocated
			current_pool[state] -= used_secX_sum;
			current_pool[state] -= used_sc_sum;

			// cap the pool at the max pool size
			if (current_pool[state] > MAX_POOL_SIZE) {
				current_pool[state] = MAX_POOL_SIZE;
			}

			// calculate the ratio of tokens allocated to the reserce
			reserve_count = (secX_count + secX_count) * RESERVE_FRACTION;
			secX_count = secX_count * (1.0 - RESERVE_FRACTION);
			sc_count = sc_count * (1.0 - RESERVE_FRACTION);

			// store how many tokens were allocated globally
			rte_atomic64_set((dos_stat.reserve[state]), reserve_count);
			dos_stat.secX_dos_packet_count[state] = secX_count;
			dos_stat.sc_dos_packet_count[state] = sc_count;

			// for each core now allocte a fraction of the allocation
			for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
				if (is_slave_core[core_id] == false) {
					continue;
				}
				core_dos_stat = dos_stats[core_id];

				dos_stats[core_id].secX_dos_packet_count[state] = secX_count / nb_slave_cores;
				previous_dos_stat[core_id].secX_dos_packet_count[state] = secX_count / nb_slave_cores;

				dos_stats[core_id].sc_dos_packet_count[state] = sc_count / nb_slave_cores;
				previous_dos_stat[core_id].sc_dos_packet_count[state] = sc_count / nb_slave_cores;
			}

			// now we repeat the process for each AS
			dict = dos_stat.dos_dictionary[state];

			// for each AS in the dictionary:
			for (int i = 0; i < dict->length; i++) {
				if (dict->table[i] != 0) {
					struct keynode_flow *k = dict->table[i];
					while (k) {
						uint64_t key = k->key;
						int64_t current_pool = k->counters->secX_counter; // yes this is not very nice dual-use
						int64_t secX_count = 0;
						int64_t sc_count = 0;
						int64_t used_secX = 0;
						int64_t used_sc = 0;
						int64_t used_secX_sum = 0;
						int64_t used_sc_sum = 0;
						int64_t refill_rate = k->counters->refill_rate; // retrieve refill rate
						int64_t MAX_POOL_SIZE = (refill_rate * MAX_POOL_SIZE_FACTOR);

						// now for each lcore aggregate again
						for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
							if (is_slave_core[core_id] == false) {
								continue;
							}

							core_dos_stat = dos_stats[core_id];
							lcore_dict = core_dos_stat.dos_dictionary[state];

							// find the dictionary node for the current AS
							dic_find_flow(lcore_dict, key);
							dic_find_flow(previous_dos_stat[core_id].dos_dictionary[state], key);
							dos_counter *value = previous_dos_stat[core_id].dos_dictionary[state]->value;

							// compute used secX tokens
							used_secX = lcore_dict->value->secX_counter;
							if (used_secX < 0) {
								used_secX_sum += labs(used_secX) + value->secX_counter;
							} else {
								used_secX_sum += value->secX_counter - used_secX;
							}

							// compute used normal SCION tokens
							used_sc = lcore_dict->value->sc_counter;
							if (used_sc < 0) {
								used_sc_sum += labs(used_sc) + value->sc_counter;
							} else {
								used_sc_sum += value->sc_counter - used_sc;
							}
						}

						// refill the pool
						current_pool += refill_rate;

						// allocate tokens
						secX_count = current_pool - used_secX_sum;
						sc_count = current_pool - used_secX_sum - used_sc_sum;

						// update the pool
						current_pool -= used_secX_sum;
						current_pool -= used_sc_sum;

						// cap the pool at max size
						if (current_pool > MAX_POOL_SIZE) {
							current_pool = MAX_POOL_SIZE;
						}

						// store the pool size again in the rat-limit dictionary node for the current AS
						k->counters->secX_counter = current_pool;

						// allocate tokens across lcores
						for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
							if (is_slave_core[core_id] == false) {
								continue;
							}

							core_dos_stat = dos_stats[core_id];
							lcore_dict = core_dos_stat.dos_dictionary[state];
							dic_find_flow(lcore_dict, key);

							// reserve allocation
							reserve_count = secX_count + secX_count * RESERVE_FRACTION;
							secX_count = secX_count * (1.0 - RESERVE_FRACTION);
							sc_count = sc_count * (1.0 - RESERVE_FRACTION);

							// set next allocations
							rte_atomic64_set(lcore_dict->value->reserve, reserve_count);
							lcore_dict->value->secX_counter = secX_count / nb_slave_cores;
							lcore_dict->value->sc_counter = sc_count / nb_slave_cores;

							// set previous allocation
							dic_find_flow(previous_dos_stat[core_id].dos_dictionary[state], key);
							previous_dos_stat[core_id].dos_dictionary[state]->value->secX_counter =
								secX_count / nb_slave_cores;
							previous_dos_stat[core_id].dos_dictionary[state]->value->sc_counter =
								sc_count / nb_slave_cores;
						}
						k = k->next;
					}
				}
			}
		}
	}
}

static int load_config(const char *path) {
	lf_config_release(&config);
	int r = lf_config_load(&config, path);
	if (r != 0) {
		RTE_ASSERT(r == -1);
		return -1;
	}

	/*
	 * The rate limits are specified as bps, we convert this to bytes / 100 micro-seconds limits are
	 * divided by 1.042 (Magic constant, I don't no why but without the rate-limits are too high)
	 */
	config.system_limit = (uint64_t)((config.system_limit / 8) / 10000)
		/ 1.042; // convert limit to bytes and shrink to 100 microseconds interval
	struct lf_config_peer *p = config.peers;
	while (p != NULL) {
		p->rate_limit = (uint64_t)((p->rate_limit / 8) / 10000)
			/ 1.042; // convert limit to bytes and shrink to 100 microseconds interval
		p = p->next;
	}

	return 0;
}

/* display CLI usage */
static void print_cli_usage(void) {
	printf(
		"Currently supported CLI commands:\n\n"
		"    stop  terminates the application\n"
		"    help  Prints this info\n\n");
}

/*
 * cli read line function
 * listens only to two commands at the moment
 * can not react to ctrl+c, so user has to call stop command if
 * CL is enabled
 */
static int cli_read_line(void) {
	int res;
	char *line = NULL;
	size_t bufsize = 0;
	res = getline(&line, &bufsize, stdin);
	if (res < 0) {
		return 1;
	}
	if (strcmp(line, "stop\n") == 0) {
		force_quit = true;
		return 0;
	} else {
		print_cli_usage();
	}
	return 1;
}

/*
 * CLI prompt user for imput and parse the input
 */
static void prompt(void) {
	int status;

	do {
		printf("> ");
		status = cli_read_line();
	} while (status);
}

static int scionfwd_launch_fwd_core(void *arg) {
	(void)arg;
	scionfwd_main_loop();
	return 0;
}

static int scionfwd_launch_dos_core(void *arg) {
	(void)arg;
	dos_main_loop();
	printf("DOS PROCESS HAS TERMINATED\n");
	return 0;
}

static int scionfwd_launch_metrics_core(void *arg) {
	(void)arg;
	metrics_main_loop();
	printf("METRICS PROCESS HAS TERMINATED\n");
	return 0;
}

static int scionfwd_launch_key_manager_core(void *arg) {
	(void)arg;
	key_manager_main_loop();
	printf("KEY MANAGER PROCESS HAS TERMINATED\n");
	return 0;
}

static int scionfwd_launch_supervisor(void) {
	printf("SUPERVISOR HAS STARTED\n");
	while (!force_quit) {
		if (is_interactive) {
			printf("\n\n");
			printf("COMMAND LINE RUNNING\n");
			printf("********************\n");
			prompt();
		}
		sleep(1);
	}
	printf("SUPERVISOR HAS TERMINATED\n");
	return 0;
}

/* display application usage */
static void scionfwd_usage(const char *prgname) {
	printf(
		"%s [EAL options] --\n"
		"  -r RX PORTMASK: hexadecimal bitmask of receive ports to configure\n"
		"  -x TX PORTMASK: hexadecimal bitmask of bypass ports to configure\n"
		"  -y TX PORTMASK: hexadecimal bitmask of firewall ports to configure\n"
		"  -i enable interactive mode\n"
		"  -l load config from scion_filter.cfg and whitelist.cfg\n"
		"  -n enable experimental smart numa alloc\n"
		"  -K NUM set key grace period\n"
		"  -S PERIOD: Set slice time (default %" PRIu64
		")\n"
		"  -E: NUM: Set num of bloom entries (default %" PRIu64
		")\n"
		"  -R: NUM: Set reciprocal value of error rate (default %" PRIu64
		")\n"
		"  -D: us: Set value of bloom filter duration (default %i)\n",
		prgname, slice_timer_period, NUM_BLOOM_ENTRIES, BLOOM_ERROR_RATE, delta_us);
}

/* convert string to portmask (int bitmap) */
static int scionfwd_parse_portmask(const char *portmask) {
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL))
		return -1;

	return pm;
}

/* parse string numbers into ints */
static int scionfwd_parse_timer_period(const char *q_arg) {
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if (q_arg[0] == '\0')
		return -1;
	if (end == NULL)
		return -2;

	return n;
}

/* command line arg requirement: define short option flags */
static const char short_options[] =
	"r:" /* receive portmask */
	"t:" /* transmit portmask */
	"x:" /* transmit bypass portmask */
	"y:" /* transmit firewall portmask */
	"n" /* enable NUMA alloc */
	"i" /* enable interactive */
	"l" /* load from config */
	"S:" /* slice timer period */
	"E:" /* bloom entries */
	"R:" /* bloom error rate */
	"D:" /* bloom interval */
	"K:" /* key grace period */
	;

/* all this is deprecated I think */
#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_ETH_DEST_NUM,

};

/* again I think the long options are deprecated,
 * the did not work when I took over this project */
static const struct option long_options[] = { { CMD_LINE_OPT_CONFIG, 1, 0,
																								CMD_LINE_OPT_CONFIG_NUM },
	{ CMD_LINE_OPT_ETH_DEST, 1, 0, CMD_LINE_OPT_ETH_DEST_NUM },
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1 },
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0 }, { NULL, 0, 0, 0 } };

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF \
	RTE_MAX((nb_ports * nb_rx_queues_per_port * RTE_TEST_RX_DESC_DEFAULT \
						+ nb_ports * nb_lcores * MAX_PKT_BURST \
						+ nb_ports * (nb_tx_bypass_queues_per_port + nb_tx_firewall_queues_per_port) \
								* RTE_TEST_TX_DESC_DEFAULT \
						+ nb_lcores * MEMPOOL_CACHE_SIZE), \
		(unsigned)8192)

/* Parse the argument given in the command line of the application */
static int scionfwd_parse_args(int argc, char **argv) {
	char *prgname = argv[0];
	int opt, timer_secs;

	optarg = NULL;
	optind = 1;
	optopt = 0;
	opterr = 0;

	while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
		switch (opt) {
			/* receiving ports */
			case 'r':
				scionfwd_rx_port_mask = scionfwd_parse_portmask(optarg);
				if (scionfwd_rx_port_mask == 0) {
					printf("invalid rx port mask\n");
					scionfwd_usage(prgname);
					return -1;
				}
				break;

			/* bypass ports */
			case 'x':
				scionfwd_tx_bypass_port_mask = scionfwd_parse_portmask(optarg);
				if (scionfwd_tx_bypass_port_mask == 0) {
					printf("invalid tx port mask\n");
					scionfwd_usage(prgname);
					return -1;
				}
				break;

			/* firewall ports */
			case 'y':
				scionfwd_tx_firewall_port_mask = scionfwd_parse_portmask(optarg);
				break;

			/* enable interactive mode */
			case 'i':
				is_interactive = 1;
				break;

			/* enable numa alloc */
			case 'n':
				numa_on = true;
				break;

			/* KEY GRACE PERIOD */
			case 'K':
				max_key_validity_extension = scionfwd_parse_timer_period(optarg);
				break;

			/* slice timer period */
			case 'S':
				timer_secs = scionfwd_parse_timer_period(optarg);
				if (timer_secs < 0) {
					printf("invalid timer period\n");
					scionfwd_usage(prgname);
					return -1;
				}
				slice_timer_period = timer_secs;
				slice_timer_period_seconds = timer_secs;
				break;

			case 'E':
				NUM_BLOOM_ENTRIES = scionfwd_parse_timer_period(optarg);
				break;

			case 'R':
				BLOOM_ERROR_RATE = scionfwd_parse_timer_period(optarg);
				break;

			case 'D':
				delta_us = scionfwd_parse_timer_period(optarg);
				break;

			case 0:
				break;

			default:
				scionfwd_usage(prgname);
				return -1;
		}
	}

	if (optind >= 0) {
		argv[optind - 1] = prgname;
	}

	return optind - 1;
}

/*
 * Initialize the memory pools used by all processing cores
 * If numa is on we initialize two pools, one per socket.
 * Otherwise we use only one pool
 * ! This currentyl works only on a machine with max two sockets !
 */
static int init_mem(unsigned nb_mbuf) {
	uint32_t gso_types;
	uint8_t socket_id, nb_sockets;
	struct rte_mempool *mbp;
	char s[64];

	printf("/* init rx queues */\n");

	if (numa_on) {
		printf("NUMA is on\n");
		nb_sockets = 2; // THIS ONLY WORKS ON THE CURRENT MACHINE SCION-R4
	} else {
		nb_sockets = 1;
	}
	// for each socket allocate a mbufpool, according to DPDK specs
	for (socket_id = 0; socket_id < nb_sockets; socket_id++) {
		snprintf(s, sizeof s, "mbuf_pool_%d", socket_id);
		scionfwd_pktmbuf_pool[socket_id] = rte_pktmbuf_pool_create(
			s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
		if (scionfwd_pktmbuf_pool[socket_id] == NULL) {
			rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n", socket_id);
		} else {
			printf("Allocated mbuf pool on socket %d with size: %d at address : %p\n", socket_id, nb_mbuf,
				scionfwd_pktmbuf_pool[socket_id]);
			printf(
				"mem pool cache size %d default size: %d\n", MEMPOOL_CACHE_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE);
		}
	}

	gso_types = DEV_TX_OFFLOAD_TCP_TSO | DEV_TX_OFFLOAD_VXLAN_TNL_TSO | DEV_TX_OFFLOAD_GRE_TNL_TSO
							| DEV_TX_OFFLOAD_UDP_TSO;

	/*
	 * Records which Mbuf pool to use by each logical core, if needed.
	 */
	for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
		if (is_slave_core[core_id] == false) {
			continue;
		}
		socket_id = rte_lcore_to_socket_id(core_id);
		mbp = scionfwd_pktmbuf_pool[socket_id];

		if (mbp == NULL) {
			mbp = scionfwd_pktmbuf_pool[0];
		}

		printf("CORE %d :: SOCKET %d :: mbp %p\n", core_id, socket_id, mbp);
		core_vars[core_id].socket_id = socket_id;
		core_vars[core_id].mbp = mbp;

		/* initialize GSO context */
		core_vars[core_id].gso_ctx.direct_pool = mbp;
		core_vars[core_id].gso_ctx.indirect_pool = mbp;
		core_vars[core_id].gso_ctx.gso_types = gso_types;
		core_vars[core_id].gso_ctx.gso_size = RTE_ETHER_MAX_LEN - RTE_ETHER_CRC_LEN;
		core_vars[core_id].gso_ctx.flag = 0;
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof link);
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
						(link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", (uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/* Signal handler
 * triggers force-quit flag */
static void signal_handler(int signum) {
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

int main(int argc, char **argv) {
	int ret;
	int nb_active_ports;
	uint8_t port_id, socket_id;
	uint32_t lcore_id = rte_lcore_id();
	uint32_t nb_lcores = 0;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;

	uint8_t ports_on_socket_0 = 0;
	uint8_t ports_on_socket_1 = 0;
	uint8_t cores_on_socket_0 = 0;
	uint8_t cores_on_socket_1 = 0;

	// set default values for two system configs
	max_key_validity_extension = DEFAULT_KEY_VALIDITY_EXTENSION;
	is_interactive = 0;

	printf("Starting SCION FW BYPASS\n\n");

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	}

	argc -= ret;
	argv += ret;

	/* register signal handlers */
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = scionfwd_parse_args(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid SCIONFWD arguments\n");
	}

	nb_active_ports = rte_eth_dev_count_avail();
	if (nb_active_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	// read rate-limit config file
	int r = load_config("config/end_hosts.cfg");
	if (r < 0) {
		rte_exit(EXIT_FAILURE, "Could not load config from provided file\n");
	}

	/* reset scionfwd_ports */
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		is_active_port[port_id] = false;
		port_values *port = &port_vars[port_id];
		port->socket_id = rte_eth_dev_socket_id(port_id);
	}

	/* count available ports */
	nb_rx_ports = (__builtin_popcount(scionfwd_rx_port_mask));
	nb_tx_bypass_ports = (__builtin_popcount(scionfwd_tx_bypass_port_mask));
	nb_tx_firewall_ports = (__builtin_popcount(scionfwd_tx_firewall_port_mask));
	nb_tx_ports = nb_tx_bypass_ports + nb_tx_firewall_ports;

	/* set port function */
	printf("\n/* set port function */\n");
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) { // ports can have multiple roles
		if ((scionfwd_rx_port_mask & (1 << port_id)) == 0) { // rx
			is_rx_port[port_id] = false;
		} else {
			is_rx_port[port_id] = true;
			is_active_port[port_id] = true;
			printf("current port: %d ->", port_id);
			printf("is rx port\n");
		}
		if ((scionfwd_tx_bypass_port_mask & (1 << port_id)) == 0) { // tx bypass
			is_tx_bypass_port[port_id] = false;
		} else {
			is_tx_bypass_port[port_id] = true;
			is_active_port[port_id] = true;
			printf("current port: %d ->", port_id);
			printf("is tx bypass port\n");
		}
		if ((scionfwd_tx_firewall_port_mask & (1 << port_id)) == 0) { // tx firewall
			is_tx_firewall_port[port_id] = false;
		} else {
			is_tx_firewall_port[port_id] = true;
			is_active_port[port_id] = true;
			printf("current port: %d ->", port_id);
			printf("is tx firewall port\n");
		}
	}

	// count the number of ports on each socket
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (is_active_port[port_id] == true) {
			nb_ports++;
			uint8_t socket_id = rte_eth_dev_socket_id(port_id);
			if (socket_id == 0) {
				ports_on_socket_0++;
			} else if (socket_id == 1) {
				ports_on_socket_1++;
			}
		}
	}

	/* count available lcores on each socket */
	uint32_t nb_available_cores = 0;
	for (int i = 0; i < RTE_MAX_LCORE; i++) {
		if (rte_lcore_is_enabled(i) == true) {
			nb_available_cores++;
			uint8_t socket_id = rte_lcore_to_socket_id(i);
			if (socket_id == 0) {
				cores_on_socket_0++;
			} else if (socket_id == 1) {
				cores_on_socket_1++;
			}
		}
	}

	// if there are less than 4 cores in the port mask return because we need at least 4 for the
	// special cores
	if (nb_available_cores < 4) {
		rte_exit(EXIT_FAILURE, "4 Cores needed for Master + Metrics + Keymanager + DOS\n");
	}

	uint32_t nb_proc_cores = nb_available_cores - 4; // one master core and this core
	nb_cores = nb_available_cores;
	nb_slave_cores = nb_proc_cores;

	RTE_ASSERT(RTE_MAX_LCORE > 0);
	RTE_ASSERT(RTE_MAX_LCORE <= SIZE_MAX);

	// print some infos
	printf("RTE_MAX_LCORE: %d\n", RTE_MAX_LCORE);
	printf("Available cores: %d + %d\n", nb_slave_cores, (nb_available_cores - nb_slave_cores));
	printf("Slave cores %d\n", nb_slave_cores);

	printf("sl: %d\n", nb_slave_cores);
	printf("rx: %d\n", nb_rx_ports);
	printf("tx_b: %d\n", nb_tx_bypass_ports);
	printf("tx_f: %d\n", nb_tx_firewall_ports);

	printf("********************\n");
	printf("PORTS ON SOCKET 0: %d\n", ports_on_socket_0);
	printf("PORTS ON SOCKET 1: %d\n", ports_on_socket_1);
	printf("CORES ON SOCKET 0: %d\n", cores_on_socket_0);
	printf("CORES ON SOCKET 1: %d\n", cores_on_socket_1);
	printf("********************\n");

	/* calculate queues and lcores per port */
	/* we assume that ratio of slave cores per socket matches the ratio of ports per socket */
	RTE_ASSERT(nb_rx_ports != 0);
	uint8_t nb_rx_queues_per_port = nb_slave_cores / nb_rx_ports;
	RTE_ASSERT(nb_tx_bypass_ports != 0);
	uint8_t nb_tx_bypass_queues_per_port = nb_slave_cores / nb_tx_bypass_ports;
	uint8_t nb_tx_firewall_queues_per_port;
	if (nb_tx_firewall_ports == 0) {
		nb_tx_firewall_queues_per_port = 0;
	} else {
		nb_tx_firewall_queues_per_port = nb_slave_cores / nb_tx_firewall_ports;
	}

	printf("nb_rx_queues_per_port: %d\n", nb_rx_queues_per_port);
	printf("nb_tx_bypass_queues_per_port: %d\n", nb_tx_bypass_queues_per_port);
	printf("nb_tx_firewall_queues_per_port: %d\n", nb_tx_firewall_queues_per_port);

	/* initialize lcore arrays */
	printf("/* initialize lcore arrays */\n");
	for (unsigned i = 0; i < RTE_MAX_LCORE; i++) {
		is_metrics_core[i] = false;
		is_key_manager_core[i] = false;
		is_slave_core[i] = false;
		is_in_use[i] = false;

		core_vars[i].rx_port_id = RTE_MAX_ETHPORTS;
		core_vars[i].tx_bypass_port_id = RTE_MAX_ETHPORTS;
		core_vars[i].tx_firewall_port_id = RTE_MAX_ETHPORTS;
	}

	/* allocate lcores */
	printf("/* allocate lcores */\n");
	bool metrics_is_set = false;
	bool key_manager_is_set = false;
	bool dos_is_set = false;

	// for every active core do the following:
	for (unsigned i = 0; i < RTE_MAX_LCORE; i++) {
		socket_id = rte_lcore_to_socket_id(i);

		if (i == rte_lcore_id()) { // CLI core (supervisor core)
			printf("current lcore id: %d | %d ->", i, socket_id);
			printf("is supervisor\n");
			is_in_use[i] = true;
			if (socket_id == 0) {
				cores_on_socket_0--;
			} else {
				cores_on_socket_1--;
			}
			continue;
		}
		if (rte_lcore_is_enabled(i) == true) {
			nb_lcores += 1;

			if (metrics_is_set == false) { // metrics core
				printf("current lcore id: %d | %d ->", i, socket_id);
				printf("is metrics\n");
				metrics_is_set = true;
				is_metrics_core[i] = true;
				is_in_use[i] = true;

				if (socket_id == 0) {
					cores_on_socket_0--;
				} else {
					cores_on_socket_1--;
				}
			} else if (dos_is_set == false) { // rate limit core
				printf("current lcore id: %d | %d ->", i, socket_id);
				printf("is DOS\n");
				dos_is_set = true;
				is_dos_core[i] = true;
				is_in_use[i] = true;

				if (socket_id == 0) {
					cores_on_socket_0--;
				} else {
					cores_on_socket_1--;
				}
			} else if (key_manager_is_set == false) { // key-manager core
				printf("current lcore id: %d | %d ->", i, socket_id);
				printf("is key_manager\n");
				key_manager_core_id = i;
				key_manager_is_set = true;
				is_key_manager_core[i] = true;
				is_in_use[i] = true;

				if (socket_id == 0) {
					cores_on_socket_0--;
				} else {
					cores_on_socket_1--;
				}
			} else if (cores_on_socket_0 > 0 && socket_id == 0) { // socket 0 cores
				printf("current lcore id: %d | %d ->", i, socket_id);
				printf("is slave\n");
				is_slave_core[i] = true;
				is_in_use[i] = true;
				cores_on_socket_0--;
			} else if (cores_on_socket_1 > 0 && socket_id == 1) { // socket 1 cores
				printf("current lcore id: %d | %d ->", i, socket_id);
				printf("is slave\n");
				is_slave_core[i] = true;
				is_in_use[i] = true;
				cores_on_socket_1--;
			}
		}
	}
	if (cores_on_socket_0 != 0 || cores_on_socket_1 != 0) {
		rte_exit(EXIT_FAILURE, "Cores are not correctly divided across the sockets");
	}

	printf("*************\n");
	printf("NB ACTIVE PORTS: %d\n", nb_ports);
	printf("NB RX PORTS: %d\n", nb_rx_ports);
	printf("NB TX PORTS: %d\n", nb_tx_ports);
	printf("NB RX BYPASS PORTS: %d\n", nb_tx_bypass_ports);
	printf("NB RX FIREWALL PORTS: %d\n", nb_tx_firewall_ports);

	if (nb_slave_cores < nb_ports) {
		rte_exit(EXIT_FAILURE, "Need at least one slave core per active port\n");
	}

	struct port_values *port;
	struct rte_ether_addr mac_addr;
	int port_socket_id;

	/* configure ports */
	printf("/* configure ports */\n");
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (is_active_port[port_id] == false) {
			continue;
		}

		port = &port_vars[port_id];
		port->dev_conf = port_conf;
		rte_eth_dev_info_get(port_id, &port->dev_info);
		rte_eth_macaddr_get(port_id, &port->eth_addr);
		port_socket_id = rte_eth_dev_socket_id(port_id);
		mac_addr = port->eth_addr;

		if (!(port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)
				|| !(port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)
				|| !(port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM))
		{
			rte_panic("TX checksum offload not supported.\n");
		}

		printf("*************\n");
		printf("Port %d: %02X:%02X:%02X:%02X:%02X:%02X\n", port_id, mac_addr.addr_bytes[0],
			mac_addr.addr_bytes[1], mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
			mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
		printf("Socket ID : %d\n", port_socket_id);

		// calculate the actual number of queues to configure
		uint8_t nb_rx_queues = 0;
		uint16_t nb_tx_queues = 0;
		if (is_rx_port[port_id]) {
			nb_rx_queues = nb_rx_queues_per_port;
		}
		if (is_tx_bypass_port[port_id]) {
			nb_tx_queues += nb_tx_bypass_queues_per_port;
		}
		if (is_tx_firewall_port[port_id]) {
			nb_tx_queues += nb_tx_firewall_queues_per_port;
		}

		// configure the queues for each port
		printf(
			"Configure port %d :: rx_queues: %d, tx_queues: %d\n", port_id, nb_rx_queues, nb_tx_queues);
		ret = rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues, &port_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret, port_id);
		}
	}

	/* init memory */
	printf("initmem arg: %d\n", NB_MBUF);
	ret = init_mem(NB_MBUF);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "init_mem failed\n");
	}

	/* init rx queues */
	printf("/* init rx queues */\n");
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		// we only care about rx ports
		if (is_rx_port[port_id] == false) {
			continue;
		}

		printf("\n\nInitializing port %d ... \n", port_id);
		// allocate rx cores
		int queue_id = 0;
		for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
			if (is_slave_core[core_id] == false) {
				continue;
			}
			if (numa_on) { // only use cores on the same socket
				if (rte_lcore_to_socket_id(core_id) != port_vars[port_id].socket_id) {
					continue;
				}
			}

			struct lcore_values *lvars = &core_vars[core_id];

			if (lvars->rx_port_id == RTE_MAX_ETHPORTS) { // only proceed if core is not allocated yet
				if (rte_lcore_to_socket_id(core_id) == port_vars[port_id].socket_id) {
					lvars->rx_port_id = port_id;
					lvars->rx_queue_id = queue_id;
					port_vars[port_id].rx_slave_core_ids[queue_id] = core_id;
					struct rte_mempool *mbp = lvars->mbp;

					socket_id = (uint8_t)rte_lcore_to_socket_id(core_id);

					printf("Initializing rx queue on lcore %u ... ", core_id);
					printf("rxq=%d,%d,%d,%p\n", lvars->rx_port_id, lvars->rx_queue_id, socket_id, mbp);
					fflush(stdout);

					// set up queue
					ret = rte_eth_rx_queue_setup(
						lvars->rx_port_id, lvars->rx_queue_id, nb_rxd, socket_id, NULL, mbp);
					if (ret < 0) {
						rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, port_id);
					}

					queue_id++;
				}
			}

			if (queue_id >= nb_rx_queues_per_port) {
				break;
			}
		}
	}

	/* initialize tx queues */
	printf("start initializing tx queues\n\n");
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		// we only care about tx ports
		if (is_tx_bypass_port[port_id] == false && is_tx_firewall_port[port_id] == false) {
			continue;
		}

		printf("\n\nInitializing port %d ... \n", port_id);
		// allocate tx cores
		int queue_id = 0;

		// bypass ports
		for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
			if (is_slave_core[core_id] == false || is_tx_bypass_port[port_id] == false) {
				continue;
			}
			if (numa_on) { // only use cores on the same socket
				if (rte_lcore_to_socket_id(core_id) != port_vars[port_id].socket_id) {
					continue;
				}
			}

			struct lcore_values *lvars = &core_vars[core_id];

			if (lvars->tx_bypass_port_id == RTE_MAX_ETHPORTS) {
				if (rte_lcore_to_socket_id(core_id) == port_vars[port_id].socket_id) {
					lvars->tx_bypass_port_id = port_id;
					lvars->tx_bypass_queue_id = queue_id;
					port_vars[port_id].tx_slave_core_ids[queue_id] = core_id;

					socket_id = (uint8_t)rte_lcore_to_socket_id(core_id);

					rte_eth_dev_info_get(port_id, &dev_info);
					txconf = &dev_info.default_txconf;

					printf("Initializing tx bypass queue on lcore %u ... ", core_id);
					printf("txq=%d,%d,%d\n", lvars->rx_port_id, lvars->rx_queue_id, socket_id);
					fflush(stdout);

					// set-up queue
					ret = rte_eth_tx_queue_setup(
						lvars->tx_bypass_port_id, lvars->tx_bypass_queue_id, nb_txd, socket_id, txconf);
					if (ret < 0) {
						rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, port_id);
					}

					queue_id++;
				}
			}

			if (queue_id >= nb_tx_bypass_queues_per_port) {
				break;
			}
		}

		// tx firewall ports

		queue_id = 0;
		for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
			if (is_slave_core[core_id] == false || is_tx_firewall_port[port_id] == false) {
				continue;
			}

			if (numa_on) {
				if (rte_lcore_to_socket_id(core_id) != port_vars[port_id].socket_id) {
					continue; // only use cores on the same socket
				}
			}

			struct lcore_values *lvars = &core_vars[core_id];
			if (lvars->tx_firewall_port_id == RTE_MAX_ETHPORTS) {
				lvars->tx_firewall_port_id = port_id;
				lvars->tx_firewall_queue_id = queue_id;
				port_vars[port_id].tx_slave_core_ids[queue_id] = core_id;

				socket_id = (uint8_t)rte_lcore_to_socket_id(core_id);
				rte_eth_dev_info_get(port_id, &dev_info);
				txconf = &dev_info.default_txconf;

				printf("Initializing tx firewall queue on lcore %u ... ", core_id);
				printf("rxq=%d,%d,%d\n", port_id, queue_id, socket_id);
				fflush(stdout);

				// set-up queue
				ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, socket_id, txconf);

				if (ret < 0) {
					rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, port_id);
				}

				queue_id++;
			}

			if (queue_id >= nb_tx_bypass_queues_per_port + nb_tx_firewall_queues_per_port) {
				break;
			}
		}
	}

	printf("\n\nStarting Ports..,");

	/* start ports */

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (is_active_port[port_id] == false) {
			continue;
		}

		// Start device //
		printf("\nSTARTING PORT: %d\n", port_id);

		ret = rte_eth_dev_start(port_id);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret, port_id);
		}

		// enable promiscuous mode on NIC
		rte_eth_promiscuous_enable(port_id);

		// we only care about tx ports
		if (is_tx_bypass_port[port_id] == false && is_tx_firewall_port[port_id] == false) {
			continue;
		}

		/* Initialize TX buffers */
		printf("initialize tx buffers...\n");
		for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
			if (is_slave_core[core_id] == false) {
				continue;
			}

			struct lcore_values *lvars = &core_vars[core_id];
			lvars->tx_bypass_buffer = rte_zmalloc_socket("tx_bypass_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0, rte_eth_dev_socket_id(port_id));
			if (lvars->tx_bypass_buffer == NULL)
				rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", (unsigned)port_id);

			rte_eth_tx_buffer_init(lvars->tx_bypass_buffer, MAX_PKT_BURST);

			if (ret < 0) {
				rte_exit(
					EXIT_FAILURE, "Cannot set error callback for tx buffer on port %u\n", (unsigned)port_id);
			}

			lvars->tx_firewall_buffer = rte_zmalloc_socket("tx_firewall_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0, rte_eth_dev_socket_id(port_id));
			if (lvars->tx_firewall_buffer == NULL)
				rte_exit(
					EXIT_FAILURE, "Cannot allocate firewall buffer for tx on port %u\n", (unsigned)port_id);

			rte_eth_tx_buffer_init(lvars->tx_firewall_buffer, MAX_PKT_BURST);

			if (ret < 0) {
				rte_exit(EXIT_FAILURE, "Cannot set error callback for firewall tx buffer on port %u\n",
					(unsigned)port_id);
			}
		}
	}

	// check the link status of all active ports and displax result
	check_all_ports_link_status((uint8_t)8,
		scionfwd_rx_port_mask | scionfwd_tx_bypass_port_mask | scionfwd_tx_firewall_port_mask);

	slice_timer_period *= rte_get_timer_hz();

#if ENABLE_MEASUREMENTS
	tsc_hz = rte_get_tsc_hz();
#endif

	// initialize the blooms filters
	printf("\nInitializing Bloom filters ...\n");
	for (int i = 0; i < RTE_MAX_LCORE; i++) {
		for (int j = 0; j < MAX_BLOOM_FILTERS; j++) {
			bloom_init(&core_vars[i].bloom_filters[j], NUM_BLOOM_ENTRIES, BLOOM_ERROR_RATE);
		}
		core_vars[i].active_filter_id = 0;
		int r = gettimeofday(&core_vars[i].last_ts, NULL);
		if (r != 0) {
			RTE_ASSERT(r == -1);
			rte_exit(EXIT_FAILURE, "Syscall gettimeofday failed.\n");
		}
		char core_id_string[12];
		sprintf(core_id_string, "%d", i);
	}

	// init key_store
	init_key_manager();

	// initializzr the rate-limiter
	printf("\nInitializing DOS...\n\n");
	init_dos();

	printf("SETUP COMPLETED\n");

	// launch special cores first
	for (unsigned core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
		if (is_in_use[core_id] == false) {
			continue;
		}

		if (is_metrics_core[core_id]) {
			rte_eal_remote_launch(scionfwd_launch_metrics_core, NULL, core_id);
		} else if (is_dos_core[core_id]) {
			rte_eal_remote_launch(scionfwd_launch_dos_core, NULL, core_id);
		} else if (is_key_manager_core[core_id]) {
			rte_eal_remote_launch(scionfwd_launch_key_manager_core, NULL, core_id);
		}
	}

	// launch slave cores -> processing cores
	for (unsigned core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
		if (is_in_use[core_id] == false) {
			continue;
		}
		if (is_slave_core[core_id]) {
			rte_eal_remote_launch(scionfwd_launch_fwd_core, NULL, core_id);
		}
	}

	// launch super visor on current core
	scionfwd_launch_supervisor();

	// if this point is reached the force-quit flag has been triggered and the applciation quits
	printf("Initiating shutdown...\n");

	// wait for all other cores
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	// close all active ports
	for (int port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (is_active_port[port_id] == false) {
			continue;
		}
		printf("Closing port %d...", port_id);
		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
		printf(" Done\n");
	}

	printf("Shutdown complete\n");

	return ret;
}
