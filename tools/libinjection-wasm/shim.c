/* Ponte mínima do libinjection para WebAssembly: memória e as duas chamadas públicas. */
#include <stdlib.h>
#include "libinjection.h"

__attribute__((export_name("tlv_alloc"))) void *tlv_alloc(size_t size) { return malloc(size); }
__attribute__((export_name("tlv_free"))) void tlv_free(void *ptr) { free(ptr); }

__attribute__((export_name("tlv_sqli"))) int tlv_sqli(const char *s, size_t len) {
    char fingerprint[8];
    return libinjection_sqli(s, len, fingerprint);
}

__attribute__((export_name("tlv_xss"))) int tlv_xss(const char *s, size_t len) { return libinjection_xss(s, len); }
