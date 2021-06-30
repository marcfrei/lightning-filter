UNAME_M = $(shell uname -m)

APP = scionfwd

SRCS-y := hashdict_flow.c json_reader.c json_reader_utils.c key_dictionary.c lf_config.c murmurhash.c scion_bloom.c scionfwd.c halfsiphash.c

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -g -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(SRCDIR)

# AESNI
ifeq ($(UNAME_M), x86_64)
	LDLIBS += -L'$(PWD)/lib/aesni'
	EXTRA_LDFLAGS += -laesni
else
	LDLIBS += -lcrypto
endif

# DRKey
LDLIBS += -L'$(PWD)/lib/drkey'
EXTRA_LDFLAGS += -ldrkey

include $(RTE_SDK)/mk/rte.extapp.mk
