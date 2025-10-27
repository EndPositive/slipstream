#include <assert.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "slipstream_utils.h"

static void test_connection_id_to_string_basic(void) {
    picoquic_connection_id_t cid = {0};
    cid.id_len = 8;
    for (uint8_t i = 0; i < cid.id_len; ++i) {
        cid.id[i] = (uint8_t)(0xf0 + i);
    }

    char *actual = picoquic_connection_id_to_string(&cid);
    assert(actual != NULL);
    assert(strcmp(actual, "f0f1f2f3f4f5f6f7") == 0);
    free(actual);
}

static void test_connection_id_to_string_empty(void) {
    picoquic_connection_id_t cid = {0};
    cid.id_len = 0;

    char *actual = picoquic_connection_id_to_string(&cid);
    assert(actual != NULL);
    assert(strcmp(actual, "") == 0);
    free(actual);
}

static void test_sockaddr_dummy_ipv4(void) {
    struct sockaddr_storage storage;
    sockaddr_dummy(&storage);

    assert(storage.ss_family == AF_INET);
    const struct sockaddr_in *addr4 = (const struct sockaddr_in *)&storage;
    char ip_str[INET_ADDRSTRLEN];
    const char *converted = inet_ntop(AF_INET, &addr4->sin_addr, ip_str, sizeof ip_str);
    assert(converted != NULL);
    assert(strcmp(ip_str, "192.0.2.1") == 0);
    assert(ntohs(addr4->sin_port) == 12345);
#ifdef __APPLE__
    assert(addr4->sin_len == sizeof(struct sockaddr_in));
#endif
}

static void test_parse_host_defaults_port(void) {
    char host[256];
    int port = 0;

    bool ok = slipstream_parse_host_port("resolver.example.com", host, sizeof(host), &port, 5300);
    assert(ok);
    assert(strcmp(host, "resolver.example.com") == 0);
    assert(port == 5300);
}

static void test_parse_host_with_port(void) {
    char host[256];
    int port = 0;

    bool ok = slipstream_parse_host_port("8.8.8.8:8053", host, sizeof(host), &port, 53);
    assert(ok);
    assert(strcmp(host, "8.8.8.8") == 0);
    assert(port == 8053);
}

static void test_parse_ipv6_bracketed(void) {
    char host[256];
    int port = 0;

    bool ok = slipstream_parse_host_port("[2001:db8::1]:8053", host, sizeof(host), &port, 53);
    assert(ok);
    assert(strcmp(host, "2001:db8::1") == 0);
    assert(port == 8053);
}

static void test_parse_ipv6_without_port(void) {
    char host[256];
    int port = 0;

    bool ok = slipstream_parse_host_port("2001:db8::2", host, sizeof(host), &port, 5300);
    assert(ok);
    assert(strcmp(host, "2001:db8::2") == 0);
    assert(port == 5300);
}

static void test_parse_rejects_invalid_port(void) {
    char host[256];
   int port = 0;

    bool ok = slipstream_parse_host_port("example.com:99999", host, sizeof(host), &port, 53);
    assert(!ok);
}

static void test_parse_rejects_malformed_ipv6(void) {
    char host[256];
    int port = 0;

    bool ok = slipstream_parse_host_port("[2001:db8::1", host, sizeof(host), &port, 53);
    assert(!ok);
}

static void test_parse_rejects_empty_host(void) {
    char host[256];
    int port = 0;

    bool ok = slipstream_parse_host_port(":5300", host, sizeof(host), &port, 53);
    assert(!ok);
}

int main(void) {
    test_connection_id_to_string_basic();
    test_connection_id_to_string_empty();
    test_sockaddr_dummy_ipv4();
    test_parse_host_defaults_port();
    test_parse_host_with_port();
    test_parse_ipv6_bracketed();
    test_parse_ipv6_without_port();
    test_parse_rejects_invalid_port();
    test_parse_rejects_malformed_ipv6();
    test_parse_rejects_empty_host();
    return 0;
}
