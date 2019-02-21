#
# Component Makefile
#

COMPONENT_ADD_INCLUDEDIRS :=  \
adapter/include	\
iotivity-constrained	\
iotivity-constrained/include \
iotivity-constrained/messaging/coap \
iotivity-constrained/security \
iotivity-constrained/util	\
iotivity-constrained/util/pt   \
iotivity-constrained/deps/mbedtls/library \
iotivity-constrained/deps/mbdetls/include/mbdetls \
iotivity-constrained/deps/tinycbor/src 

COMPONENT_OBJS =  \
iotivity-constrained/deps/tinycbor/src/cborencoder.o	\
iotivity-constrained/deps/tinycbor/src/cborencoder_close_container_checked.o	\
iotivity-constrained/deps/tinycbor/src/cborparser.o	\
\
iotivity-constrained/deps/mbedtls/library/aes.o \
iotivity-constrained/deps/mbedtls/library/aesni.o \
iotivity-constrained/deps/mbedtls/library/arc4.o \
iotivity-constrained/deps/mbedtls/library/asn1parse.o \
iotivity-constrained/deps/mbedtls/library/asn1write.o \
iotivity-constrained/deps/mbedtls/library/base64.o \
iotivity-constrained/deps/mbedtls/library/bignum.o \
iotivity-constrained/deps/mbedtls/library/blowfish.o \
iotivity-constrained/deps/mbedtls/library/camellia.o \
iotivity-constrained/deps/mbedtls/library/ccm.o \
iotivity-constrained/deps/mbedtls/library/certs.o \
iotivity-constrained/deps/mbedtls/library/cipher.o \
iotivity-constrained/deps/mbedtls/library/cipher_wrap.o \
iotivity-constrained/deps/mbedtls/library/cmac.o \
iotivity-constrained/deps/mbedtls/library/ctr_drbg.o \
iotivity-constrained/deps/mbedtls/library/des.o \
iotivity-constrained/deps/mbedtls/library/dhm.o \
iotivity-constrained/deps/mbedtls/library/ecdh.o \
iotivity-constrained/deps/mbedtls/library/ecdsa.o \
iotivity-constrained/deps/mbedtls/library/ecjpake.o \
iotivity-constrained/deps/mbedtls/library/ecp.o \
iotivity-constrained/deps/mbedtls/library/ecp_curves.o \
iotivity-constrained/deps/mbedtls/library/entropy.o \
iotivity-constrained/deps/mbedtls/library/entropy_poll.o \
iotivity-constrained/deps/mbedtls/library/error.o \
iotivity-constrained/deps/mbedtls/library/gcm.o \
iotivity-constrained/deps/mbedtls/library/havege.o \
iotivity-constrained/deps/mbedtls/library/hmac_drbg.o \
iotivity-constrained/deps/mbedtls/library/md.o \
iotivity-constrained/deps/mbedtls/library/md2.o \
iotivity-constrained/deps/mbedtls/library/md4.o \
iotivity-constrained/deps/mbedtls/library/md5.o \
iotivity-constrained/deps/mbedtls/library/md_wrap.o \
iotivity-constrained/deps/mbedtls/library/oid.o \
iotivity-constrained/deps/mbedtls/library/padlock.o \
iotivity-constrained/deps/mbedtls/library/pem.o \
iotivity-constrained/deps/mbedtls/library/pk.o \
iotivity-constrained/deps/mbedtls/library/pk_wrap.o \
iotivity-constrained/deps/mbedtls/library/pkcs12.o \
iotivity-constrained/deps/mbedtls/library/pkcs5.o \
iotivity-constrained/deps/mbedtls/library/pkparse.o \
iotivity-constrained/deps/mbedtls/library/pkwrite.o \
iotivity-constrained/deps/mbedtls/library/platform.o \
iotivity-constrained/deps/mbedtls/library/ripemd160.o \
iotivity-constrained/deps/mbedtls/library/rsa.o \
iotivity-constrained/deps/mbedtls/library/sha1.o \
iotivity-constrained/deps/mbedtls/library/sha256.o \
iotivity-constrained/deps/mbedtls/library/sha512.o \
iotivity-constrained/deps/mbedtls/library/threading.o \
iotivity-constrained/deps/mbedtls/library/timing.o \
iotivity-constrained/deps/mbedtls/library/version.o \
iotivity-constrained/deps/mbedtls/library/version_features.o \
iotivity-constrained/deps/mbedtls/library/xtea.o \
iotivity-constrained/deps/mbedtls/library/pkcs11.o \
iotivity-constrained/deps/mbedtls/library/x509.o \
iotivity-constrained/deps/mbedtls/library/x509_crt.o \
iotivity-constrained/deps/mbedtls/library/debug.o \
iotivity-constrained/deps/mbedtls/library/net_sockets.o \
iotivity-constrained/deps/mbedtls/library/ssl_cache.o \
iotivity-constrained/deps/mbedtls/library/ssl_ciphersuites.o \
iotivity-constrained/deps/mbedtls/library/ssl_cli.o \
iotivity-constrained/deps/mbedtls/library/ssl_cookie.o \
iotivity-constrained/deps/mbedtls/library/ssl_srv.o \
iotivity-constrained/deps/mbedtls/library/ssl_ticket.o \
iotivity-constrained/deps/mbedtls/library/ssl_tls.o \
iotivity-constrained/deps/mbedtls/library/rsa_internal.o \
iotivity-constrained/deps/mbedtls/library/x509write_csr.o \
iotivity-constrained/deps/mbedtls/library/x509write_crt.o \
iotivity-constrained/deps/mbedtls/library/x509_create.o \
\
adapter/src/random.o	\
adapter/src/storage.o	\
adapter/src/clock.o		\
adapter/src/ipadapter.o	\
adapter/src/abort.o		\
adapter/src/debug_print.o	\
\
iotivity-constrained/util/oc_etimer.o \
iotivity-constrained/util/oc_list.o \
iotivity-constrained/util/oc_memb.o \
iotivity-constrained/util/oc_mmem.o \
iotivity-constrained/util/oc_process.o \
iotivity-constrained/util/oc_timer.o \
\
iotivity-constrained/api/oc_base64.o \
iotivity-constrained/api/oc_blockwise.o \
iotivity-constrained/api/oc_buffer.o \
iotivity-constrained/api/oc_client_api.o \
iotivity-constrained/api/oc_collection.o \
iotivity-constrained/api/oc_core_res.o \
iotivity-constrained/api/oc_discovery.o \
iotivity-constrained/api/oc_endpoint.o \
iotivity-constrained/api/oc_helpers.o \
iotivity-constrained/api/oc_introspection.o \
iotivity-constrained/api/oc_main.o \
iotivity-constrained/api/oc_network_events.o \
iotivity-constrained/api/oc_rep.o \
iotivity-constrained/api/oc_ri.o \
iotivity-constrained/api/oc_server_api.o \
iotivity-constrained/api/oc_uuid.o \
iotivity-constrained/api/oc_session_events.o \
\
iotivity-constrained/security/oc_acl.o\
iotivity-constrained/security/oc_cred.o\
iotivity-constrained/security/oc_doxm.o\
iotivity-constrained/security/oc_obt.o\
iotivity-constrained/security/oc_pstat.o\
iotivity-constrained/security/oc_store.o\
iotivity-constrained/security/oc_svr.o\
iotivity-constrained/security/oc_roles.o\
iotivity-constrained/security/oc_pki.o\
iotivity-constrained/security/oc_sp.o\
iotivity-constrained/security/oc_certs.o\
iotivity-constrained/security/oc_csr.o\
iotivity-constrained/security/oc_keypair.o\
iotivity-constrained/security/oc_sp.o\
iotivity-constrained/security/oc_tls.o\
\
iotivity-constrained/messaging/coap/coap_signal.o\
iotivity-constrained/messaging/coap/coap.o	\
iotivity-constrained/messaging/coap/engine.o	\
iotivity-constrained/messaging/coap/observe.o	\
iotivity-constrained/messaging/coap/separate.o	\
iotivity-constrained/messaging/coap/transactions.o	

COMPONENT_SRCDIRS :=  \
iotivity-constrained/util  \
iotivity-constrained/include \
iotivity-constrained/security \
iotivity-constrained/api \
iotivity-constrained/messaging/coap	\
iotivity-constrained/deps/tinycbor/src	\
iotivity-constrained/deps/mbedtls/library \
iotivity-constrained/deps/mbedtls/include/mbedtls \
adapter/src
