#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

export PROJECT_PATH := $(PWD)
export IDF_PATH ?= $(PWD)/esp-idf

ifeq ($(CLIENT), 1)
	PROJECT_NAME := iotivity_client
endif
	
ifeq ($(SERVER), 1)
	PROJECT_NAME := iotivity_server
endif
##
##
ifeq ($(BLINKERCLIENT),1)
    PROJECT_NAME := esp32_blinker_client
endif

ifeq ($(BLINKERSERVER),1)
    PROJECT_NAME := esp32_blinker_server
endif

PROJECT_NAME ?= esp32_iotivity

include $(IDF_PATH)/make/project.mk

# sdkconfig is included project.mk recursively
# after setting sdkconfig done, start user layer macro define  
ifdef CONFIG_IOTIVITY_CLIENT
    CFLAGS += -DOC_CLIENT
endif

ifdef CONFIG_IOTIVITY_SERVER
    CFLAGS += -DOC_SERVER
endif

ifdef CONFIG_IOTIVITY_CLIENT_BLINKER
    CFLAGS += -DOC_CLIENT
endif

ifdef CONFIG_IOTIVITY_SERVER_BLINKER
    CFLAGS += -DOC_SERVER
endif

ifdef CONFIG_OC_DEBUG
    CFLAGS += -DOC_DEBUG
endif

ifdef CONFIG_APP_DEBUG
    CFLAGS += -DAPP_DEBUG
endif

ifdef CONFIG_ENABLE_LIGHT
    CFLAGS += -DENABLE_LIGHT
endif

ifdef CONFIG_DYNAMIC
    CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifdef CONFIG_SECURE
    CFLAGS += -DOC_SECURITY
endif

ifdef CONFIG_IPV4
    CFLAGS += -DOC_IPV4
endif

ifdef CONFIG_TCP
    CFLAGS += -DOC_TCP
endif


ifdef CONFIG_PKI
    CFLAGS += -DOC_PKI
    CFLAGS += -DMBEDTLS_X509_EXPANDED_SUBJECT_ALT_NAME_SUPPORT
    CFLAGS += -DMBEDTLS_SHA256_C
    CFLAGS += -DMBEDTLS_ECP_DP_SECP256R1_ENABLED
    CFLAGS += -DMBEDTLS_RSA_C
    CFLAGS += -DMBEDTLS_ECDSA_C
    CFLAGS += -DMBEDTLS_CERTS_C
endif