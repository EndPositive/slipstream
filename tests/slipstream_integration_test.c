#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "SPCDNS/src/dns.h"
#include "slipstream_inline_dots.h"
#include "slipstream_slot.h"

ssize_t client_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf,
                      size_t src_buf_len, size_t* segment_len, struct sockaddr_storage* peer_addr,
                      struct sockaddr_storage* local_addr);
ssize_t client_decode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf,
                      size_t src_buf_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr);
ssize_t server_decode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf,
                      size_t src_buf_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr);
ssize_t server_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf,
                      size_t src_buf_len, size_t* segment_len, struct sockaddr_storage* peer_addr,
                      struct sockaddr_storage* local_addr);

extern char* client_domain_name;
extern size_t client_domain_name_len;
extern char* server_domain_name;
extern size_t server_domain_name_len;

static char client_domain_buffer[256];
static char server_domain_buffer[256];

static void configure_domains(const char* domain) {
    const size_t len = strlen(domain);
    assert(len < sizeof client_domain_buffer);
    memcpy(client_domain_buffer, domain, len + 1);
    memcpy(server_domain_buffer, domain, len + 1);
    client_domain_name = client_domain_buffer;
    client_domain_name_len = len;
    server_domain_name = server_domain_buffer;
    server_domain_name_len = len;
}

static void test_client_server_roundtrip_single_segment(void) {
    configure_domains("example.com");

    const unsigned char payload[] = "slipstream-integration";
    struct sockaddr_storage dummy_peer = {0};
    dummy_peer.ss_family = AF_INET;
    struct sockaddr_storage dummy_local = {0};
    dummy_local.ss_family = AF_INET6;

    unsigned char* encoded_packets = NULL;
    size_t segment_len = MAX_DNS_QUERY_SIZE;

    ssize_t encoded_len = client_encode(NULL, NULL, &encoded_packets, payload, sizeof payload, &segment_len,
        &dummy_peer, &dummy_local);
    assert(encoded_len > 0);
    assert(segment_len > 0);
    assert(encoded_packets != NULL);

    slot_t slot = {0};
    unsigned char* decoded_payload = NULL;
    struct sockaddr_storage incoming_peer = dummy_peer;
    struct sockaddr_storage incoming_local = dummy_local;

    ssize_t decoded_len = server_decode(&slot, NULL, &decoded_payload, encoded_packets, (size_t)encoded_len,
        &incoming_peer, &incoming_local);
    assert(decoded_len == (ssize_t)sizeof payload);
    assert(decoded_payload != NULL);
    assert(memcmp(decoded_payload, payload, sizeof payload) == 0);

    unsigned char* response_packet = NULL;
    struct sockaddr_storage response_peer = {0};
    struct sockaddr_storage response_local = {0};
    ssize_t response_len = server_encode(&slot, NULL, &response_packet, decoded_payload, (size_t)decoded_len,
        NULL, &response_peer, &response_local);
    assert(response_len > 0);
    assert(response_packet != NULL);
    free(decoded_payload);

    unsigned char* client_received = NULL;
    struct sockaddr_storage reply_peer = {0};
    struct sockaddr_storage reply_local = {0};
    ssize_t client_len = client_decode(NULL, NULL, &client_received, response_packet, (size_t)response_len,
        &reply_peer, &reply_local);
    assert(client_len == (ssize_t)sizeof payload);
    assert(client_received != NULL);
    assert(memcmp(client_received, payload, sizeof payload) == 0);

    free(client_received);
    free(response_packet);
    free(encoded_packets);
}

static void test_server_empty_payload_returns_name_error(void) {
    configure_domains("example.com");

    const unsigned char payload[] = "noop";
    struct sockaddr_storage dummy_peer = {0};
    dummy_peer.ss_family = AF_INET;
    struct sockaddr_storage dummy_local = {0};
    dummy_local.ss_family = AF_INET6;

    unsigned char* encoded_packets = NULL;
    size_t segment_len = MAX_DNS_QUERY_SIZE;
    ssize_t encoded_len = client_encode(NULL, NULL, &encoded_packets, payload, sizeof payload, &segment_len,
        &dummy_peer, &dummy_local);
    assert(encoded_len > 0);

    slot_t slot = {0};
    unsigned char* decoded_payload = NULL;
    struct sockaddr_storage incoming_peer = dummy_peer;
    struct sockaddr_storage incoming_local = dummy_local;
    ssize_t decoded_len = server_decode(&slot, NULL, &decoded_payload, encoded_packets, (size_t)encoded_len,
        &incoming_peer, &incoming_local);
    assert(decoded_len == (ssize_t)sizeof payload);
    free(decoded_payload);

    unsigned char* response_packet = NULL;
    struct sockaddr_storage response_peer = {0};
    struct sockaddr_storage response_local = {0};
    ssize_t response_len = server_encode(&slot, NULL, &response_packet, NULL, 0, NULL,
        &response_peer, &response_local);
    assert(response_len > 0);

    unsigned char* client_received = NULL;
    struct sockaddr_storage reply_peer = {0};
    struct sockaddr_storage reply_local = {0};
    ssize_t client_len = client_decode(NULL, NULL, &client_received, response_packet, (size_t)response_len,
        &reply_peer, &reply_local);
    assert(client_len == 0);
    assert(client_received == NULL);

    free(response_packet);
    free(encoded_packets);
}

static void test_server_decode_corrupt_base32_sets_servfail(void) {
    configure_domains("example.com");

    const unsigned char payload[] = "slipstream-negative-test";
    struct sockaddr_storage dummy_peer = {0};
    dummy_peer.ss_family = AF_INET;
    struct sockaddr_storage dummy_local = {0};
    dummy_local.ss_family = AF_INET6;

    unsigned char* encoded_packets = NULL;
    size_t segment_len = MAX_DNS_QUERY_SIZE;
    ssize_t encoded_len = client_encode(NULL, NULL, &encoded_packets, payload, sizeof payload, &segment_len,
        &dummy_peer, &dummy_local);
    assert(encoded_len > 0);

    /* Corrupt the Base32 payload so the server should emit SERVFAIL. */
    const size_t header_len = 12;
    assert((size_t)encoded_len > header_len + 1);
    encoded_packets[header_len + 1] = '!';

    slot_t slot = {0};
    unsigned char* decoded_payload = NULL;
    struct sockaddr_storage incoming_peer = dummy_peer;
    struct sockaddr_storage incoming_local = dummy_local;
    ssize_t decoded_len = server_decode(&slot, NULL, &decoded_payload, encoded_packets, (size_t)encoded_len,
        &incoming_peer, &incoming_local);
    assert(decoded_len == 0);
    assert(decoded_payload == NULL);
    assert(slot.error == RCODE_SERVER_FAILURE);

    free(encoded_packets);
}

static void test_server_decode_multiple_questions_sets_format_error(void) {
    configure_domains("example.com");

    const unsigned char payload[] = "slipstream-format-test";
    struct sockaddr_storage dummy_peer = {0};
    dummy_peer.ss_family = AF_INET;
    struct sockaddr_storage dummy_local = {0};
    dummy_local.ss_family = AF_INET6;

    unsigned char* encoded_packets = NULL;
    size_t segment_len = MAX_DNS_QUERY_SIZE;
    ssize_t encoded_len = client_encode(NULL, NULL, &encoded_packets, payload, sizeof payload, &segment_len,
        &dummy_peer, &dummy_local);
    assert(encoded_len > 0);

    dns_decoded_t decoded_buf[DNS_DECODEBUF_4K];
    size_t decode_len = sizeof(decoded_buf);
    dns_rcode_t decode_rc = dns_decode(decoded_buf, &decode_len,
        (const dns_packet_t*)encoded_packets, (size_t)encoded_len);
    assert(decode_rc == RCODE_OKAY);

    dns_query_t* base_query = (dns_query_t*)decoded_buf;
    assert(base_query->qdcount == 1);
    dns_question_t questions[2];
    questions[0] = base_query->questions[0];
    questions[1] = base_query->questions[0];

    dns_query_t multi_query = {0};
    multi_query.id = base_query->id;
    multi_query.query = base_query->query;
    multi_query.opcode = base_query->opcode;
    multi_query.aa = base_query->aa;
    multi_query.tc = base_query->tc;
    multi_query.rd = base_query->rd;
    multi_query.ra = base_query->ra;
    multi_query.z = base_query->z;
    multi_query.ad = base_query->ad;
    multi_query.cd = base_query->cd;
    multi_query.rcode = base_query->rcode;
    multi_query.qdcount = 2;
    multi_query.ancount = 0;
    multi_query.nscount = 0;
    multi_query.arcount = 0;
    multi_query.questions = questions;
    multi_query.answers = NULL;
    multi_query.nameservers = NULL;
    multi_query.additional = NULL;

    dns_packet_t* multi_question_packet = malloc(MAX_DNS_QUERY_SIZE);
    assert(multi_question_packet != NULL);
    size_t multi_len = MAX_DNS_QUERY_SIZE;
    dns_rcode_t encode_rc = dns_encode(multi_question_packet, &multi_len, &multi_query);
    assert(encode_rc == RCODE_OKAY);

    slot_t slot = {0};
    unsigned char* decoded_payload = NULL;
    struct sockaddr_storage incoming_peer = dummy_peer;
    struct sockaddr_storage incoming_local = dummy_local;
    ssize_t decoded_len = server_decode(&slot, NULL, &decoded_payload, multi_question_packet,
        multi_len, &incoming_peer, &incoming_local);
    assert(decoded_len == 0);
    assert(decoded_payload == NULL);
    assert(slot.error == RCODE_FORMAT_ERROR);

    free(multi_question_packet);
    free(encoded_packets);
}

int main(void) {
    test_client_server_roundtrip_single_segment();
    test_server_empty_payload_returns_name_error();
    test_server_decode_corrupt_base32_sets_servfail();
    test_server_decode_multiple_questions_sets_format_error();
    return 0;
}
