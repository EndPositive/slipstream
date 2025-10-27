#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "SPCDNS/src/dns.h"
#include "lua-resty-base-encoding-base32.h"
#include "slipstream_inline_dots.h"
#include "slipstream_slot.h"

ssize_t server_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len,
                      size_t* segment_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr);
ssize_t server_decode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len,
                      struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr);

extern char* server_domain_name;
extern size_t server_domain_name_len;

static void set_server_domain(const char* domain) {
    server_domain_name = (char*)domain;
    server_domain_name_len = strlen(domain);
}

static void build_query_packet(const unsigned char* payload, size_t payload_len, unsigned char* packet_buf, size_t* packet_len) {
    char encoded_name[255];
    size_t encoded_len = b32_encode(encoded_name, (const char*)payload, payload_len, true, false);
    size_t dotted_len = slipstream_inline_dotify(encoded_name, sizeof encoded_name, encoded_len);
    encoded_name[dotted_len] = '\0';

    char fqdn[512];
    snprintf(fqdn, sizeof fqdn, "%s.%s.", encoded_name, server_domain_name);

    dns_question_t question = {0};
    question.name = fqdn;
    question.type = RR_TXT;
    question.class = CLASS_IN;

    dns_query_t query = {0};
    query.id = 7;
    query.query = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &question;

    dns_rcode_t rc = dns_encode((dns_packet_t*)packet_buf, packet_len, &query);
    assert(rc == RCODE_OKAY);
}

static void test_server_decode_valid_query(void) {
    set_server_domain("example.com");

    const unsigned char payload[] = "ping";
    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    build_query_packet(payload, strlen((const char*)payload), packet_buf, &packet_len);

    slot_t slot = {0};
    struct sockaddr_storage peer = {0};
    peer.ss_family = AF_INET;
    struct sockaddr_storage local = {0};
    local.ss_family = AF_INET6;
    unsigned char* decoded = NULL;

    ssize_t decoded_len = server_decode(&slot, NULL, &decoded, packet_buf, packet_len, &peer, &local);
    assert(decoded_len == (ssize_t)strlen((const char*)payload));
    assert(decoded != NULL);
    assert(memcmp(decoded, payload, strlen((const char*)payload)) == 0);
    free(decoded);

    assert(slot.error == RCODE_OKAY);
    assert(slot.peer_addr.ss_family == AF_INET);
    assert(slot.local_addr.ss_family == AF_INET6);
    assert(peer.ss_family == AF_INET); // sockaddr_dummy keeps AF_INET but rewrites address/port
}

static void test_server_decode_rejects_non_txt(void) {
    set_server_domain("example.com");

    const unsigned char payload[] = "ignored";
    char encoded_name[255];
    size_t encoded_len = b32_encode(encoded_name, (const char*)payload, strlen((const char*)payload), true, false);
    size_t dotted_len = slipstream_inline_dotify(encoded_name, sizeof encoded_name, encoded_len);
    encoded_name[dotted_len] = '\0';

    char fqdn[512];
    snprintf(fqdn, sizeof fqdn, "%s.%s.", encoded_name, server_domain_name);

    dns_question_t question = {0};
    question.name = fqdn;
    question.type = RR_A;
    question.class = CLASS_IN;

    dns_query_t query = {0};
    query.id = 8;
    query.query = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &question;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &query);
    assert(rc == RCODE_OKAY);

    slot_t slot = {0};
    unsigned char* decoded = NULL;
    struct sockaddr_storage peer = {0};
    struct sockaddr_storage local = {0};

    ssize_t len = server_decode(&slot, NULL, &decoded, packet_buf, packet_len, &peer, &local);
    assert(len == 0);
    assert(decoded == NULL);
    assert(slot.error == RCODE_NAME_ERROR);
}

static void test_server_decode_rejects_multiple_questions(void) {
    set_server_domain("example.com");

    const unsigned char payload[] = "ignored";
    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;

    char encoded_name[255];
    size_t encoded_len = b32_encode(encoded_name, (const char*)payload, strlen((const char*)payload), true, false);
    size_t dotted_len = slipstream_inline_dotify(encoded_name, sizeof encoded_name, encoded_len);
    encoded_name[dotted_len] = '\0';

    char fqdn[512];
    snprintf(fqdn, sizeof fqdn, "%s.%s.", encoded_name, server_domain_name);

    dns_question_t questions[2] = {0};
    questions[0].name = fqdn;
    questions[0].type = RR_TXT;
    questions[0].class = CLASS_IN;
    questions[1] = questions[0];

    dns_query_t query = {0};
    query.id = 12;
    query.query = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 2;
    query.questions = questions;

    dns_rcode_t rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &query);
    assert(rc == RCODE_OKAY);

    slot_t slot = {0};
    unsigned char* decoded = NULL;
    struct sockaddr_storage peer = {0};
    struct sockaddr_storage local = {0};

    ssize_t len = server_decode(&slot, NULL, &decoded, packet_buf, packet_len, &peer, &local);
    assert(len == 0);
    assert(decoded == NULL);
    assert(slot.error == RCODE_FORMAT_ERROR);
}

static void test_server_decode_handles_bad_base32(void) {
    set_server_domain("example.com");

    const char* fqdn = "invalid!characters.example.com.";
    dns_question_t question = {0};
    question.name = (char*)fqdn;
    question.type = RR_TXT;
    question.class = CLASS_IN;

    dns_query_t query = {0};
    query.id = 9;
    query.query = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &question;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &query);
    assert(rc == RCODE_OKAY);

    slot_t slot = {0};
    unsigned char* decoded = NULL;
    struct sockaddr_storage peer = {0};
    struct sockaddr_storage local = {0};

    ssize_t len = server_decode(&slot, NULL, &decoded, packet_buf, packet_len, &peer, &local);
    assert(len == 0);
    assert(decoded == NULL);
    assert(slot.error == RCODE_SERVER_FAILURE);
}

static void test_server_decode_rejects_missing_question(void) {
    set_server_domain("example.com");

    dns_query_t query = {0};
    query.id = 10;
    query.query = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 0;
    query.questions = NULL;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &query);
    assert(rc == RCODE_OKAY);

    slot_t slot = {0};
    unsigned char* decoded = NULL;
    struct sockaddr_storage peer = {0};
    struct sockaddr_storage local = {0};

    ssize_t len = server_decode(&slot, NULL, &decoded, packet_buf, packet_len, &peer, &local);
    assert(len == 0);
    assert(decoded == NULL);
    assert(slot.error == RCODE_FORMAT_ERROR);
}

static void test_server_decode_rejects_empty_subdomain(void) {
    set_server_domain("example.com");

    dns_question_t question = {0};
    question.name = "example.com.";
    question.type = RR_TXT;
    question.class = CLASS_IN;

    dns_query_t query = {0};
    query.id = 11;
    query.query = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &question;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &query);
    assert(rc == RCODE_OKAY);

    slot_t slot = {0};
    unsigned char* decoded = NULL;
    struct sockaddr_storage peer = {0};
    struct sockaddr_storage local = {0};

    ssize_t len = server_decode(&slot, NULL, &decoded, packet_buf, packet_len, &peer, &local);
    assert(len == 0);
    assert(decoded == NULL);
    assert(slot.error == RCODE_NAME_ERROR);
}

static void test_server_encode_with_payload(void) {
    set_server_domain("example.com");

    const unsigned char query_payload[] = "hello";
    unsigned char query_packet[MAX_UDP_PACKET_SIZE] = {0};
    size_t query_packet_len = sizeof query_packet;
    build_query_packet(query_payload, strlen((const char*)query_payload), query_packet, &query_packet_len);

    slot_t slot = {0};
    struct sockaddr_storage original_peer = {0};
    original_peer.ss_family = AF_INET;
    struct sockaddr_storage original_local = {0};
    original_local.ss_family = AF_INET;

    unsigned char* decoded = NULL;
    ssize_t decoded_len = server_decode(&slot, NULL, &decoded, query_packet, query_packet_len, &original_peer, &original_local);
    assert(decoded_len == (ssize_t)strlen((const char*)query_payload));
    free(decoded);

    slot.error = RCODE_OKAY;
    slot.peer_addr = original_peer;
    slot.local_addr = original_local;

    const unsigned char response_payload[] = "world";
    unsigned char* encoded = NULL;
    struct sockaddr_storage out_peer = {0};
    struct sockaddr_storage out_local = {0};

    ssize_t encoded_len = server_encode(&slot, NULL, &encoded, response_payload, strlen((const char*)response_payload), NULL, &out_peer, &out_local);
    assert(encoded_len > 0);
    assert(encoded != NULL);

    dns_decoded_t decoded_buf[DNS_DECODEBUF_4K] = {0};
    size_t decoded_buf_len = sizeof decoded_buf;
    dns_rcode_t rc = dns_decode(decoded_buf, &decoded_buf_len, (dns_packet_t*)encoded, encoded_len);
    assert(rc == RCODE_OKAY);

    const dns_query_t* response = (const dns_query_t*)decoded_buf;
    assert(response->query == false);
    assert(response->rcode == RCODE_OKAY);
    assert(response->ancount == 1);
    assert(response->answers != NULL);

    const dns_txt_t* answer_txt = (const dns_txt_t*)&response->answers[0];
    assert(answer_txt->len == strlen((const char*)response_payload));
    assert(memcmp(answer_txt->text, response_payload, answer_txt->len) == 0);

    assert(out_peer.ss_family == original_peer.ss_family);
    assert(out_local.ss_family == original_local.ss_family);

    free(encoded);
}

static void test_server_encode_empty_payload_sets_name_error(void) {
    set_server_domain("example.com");

    const unsigned char query_payload[] = "noop";
    unsigned char query_packet[MAX_UDP_PACKET_SIZE] = {0};
    size_t query_packet_len = sizeof query_packet;
    build_query_packet(query_payload, strlen((const char*)query_payload), query_packet, &query_packet_len);

    slot_t slot = {0};
    struct sockaddr_storage original_peer = {0};
    struct sockaddr_storage original_local = {0};
    unsigned char* decoded = NULL;

    ssize_t decoded_len = server_decode(&slot, NULL, &decoded, query_packet, query_packet_len, &original_peer, &original_local);
    assert(decoded_len > 0);
    free(decoded);

    slot.error = RCODE_OKAY;
    slot.peer_addr = original_peer;
    slot.local_addr = original_local;

    unsigned char* encoded = NULL;
    struct sockaddr_storage out_peer = {0};
    struct sockaddr_storage out_local = {0};

    ssize_t encoded_len = server_encode(&slot, NULL, &encoded, NULL, 0, NULL, &out_peer, &out_local);
    assert(encoded_len > 0);
    assert(encoded != NULL);

    dns_decoded_t decoded_buf[DNS_DECODEBUF_4K] = {0};
    size_t decoded_buf_len = sizeof decoded_buf;
    dns_rcode_t rc = dns_decode(decoded_buf, &decoded_buf_len, (dns_packet_t*)encoded, encoded_len);
    assert(rc == RCODE_OKAY);

    const dns_query_t* response = (const dns_query_t*)decoded_buf;
    assert(response->rcode == RCODE_NAME_ERROR);
    assert(response->ancount == 0);

    free(encoded);
}

int main(void) {
    test_server_decode_valid_query();
    test_server_decode_rejects_non_txt();
    test_server_decode_rejects_multiple_questions();
    test_server_decode_handles_bad_base32();
    test_server_decode_rejects_missing_question();
    test_server_decode_rejects_empty_subdomain();
    test_server_encode_with_payload();
    test_server_encode_empty_payload_sets_name_error();
    return 0;
}
