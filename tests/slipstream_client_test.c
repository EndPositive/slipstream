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

ssize_t client_encode_segment(dns_packet_t* packet, size_t* packet_len, const unsigned char* src_buf, size_t src_buf_len);
ssize_t client_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len,
                      size_t* segment_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr);
ssize_t client_decode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len,
                      struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr);

extern char* client_domain_name;
extern size_t client_domain_name_len;

static void set_client_domain(const char* domain) {
    client_domain_name = (char*)domain;
    client_domain_name_len = strlen(domain);
}

static void test_client_encode_segment_appends_domain(void) {
    set_client_domain("example.com");

    const unsigned char payload[] = "hello";
    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;

    ssize_t rc = client_encode_segment((dns_packet_t*)packet_buf, &packet_len, payload, strlen((const char*)payload));
    assert(rc == 0);
    assert(packet_len > 0);

    dns_decoded_t decoded[DNS_DECODEBUF_4K] = {0};
    size_t decoded_len = sizeof decoded;
    dns_rcode_t decode_rc = dns_decode(decoded, &decoded_len, (dns_packet_t*)packet_buf, packet_len);
    assert(decode_rc == RCODE_OKAY);

    const dns_query_t* query = (const dns_query_t*)decoded;
    assert(query->query == true);
    assert(query->qdcount == 1);
    assert(query->questions != NULL);
    const dns_question_t* question = &query->questions[0];
    assert(question->type == RR_TXT);
    assert(question->class == CLASS_IN);

    char expected_subdomain[255];
    char expected_name[512];
    size_t encoded_len = b32_encode(expected_subdomain, (const char*)payload, strlen((const char*)payload), true, false);
    size_t dotted_len = slipstream_inline_dotify(expected_subdomain, sizeof expected_subdomain, encoded_len);
    expected_subdomain[dotted_len] = '\0';
    snprintf(expected_name, sizeof expected_name, "%s.%s.", expected_subdomain, "example.com");

    assert(strcmp(question->name, expected_name) == 0);
}

static void test_client_encode_handles_segmentation(void) {
    set_client_domain("example.com");

    unsigned char payload[64];
    memset(payload, 'A', sizeof payload);
    const size_t requested_segment = 32;
    size_t segment_len = requested_segment;
    unsigned char* encoded_packets = NULL;
    struct sockaddr_storage dummy_peer = {0};
    struct sockaddr_storage dummy_local = {0};

    ssize_t total_len = client_encode(NULL, NULL, &encoded_packets, payload, sizeof payload, &segment_len, &dummy_peer, &dummy_local);
    assert(total_len > 0);
    assert(encoded_packets != NULL);
    assert(segment_len > 0);
    assert(total_len % segment_len == 0);
    size_t packet_count = total_len / segment_len;
    assert(packet_count == sizeof(payload) / requested_segment);

    for (size_t i = 0; i < packet_count; ++i) {
        dns_decoded_t decoded[DNS_DECODEBUF_4K] = {0};
        size_t decoded_len = sizeof decoded;
        unsigned char* packet = encoded_packets + (i * segment_len);
        dns_rcode_t rc = dns_decode(decoded, &decoded_len, (dns_packet_t*)packet, segment_len);
        assert(rc == RCODE_OKAY);

        const dns_query_t* query = (const dns_query_t*)decoded;
        assert(query->qdcount == 1);
        const dns_question_t* question = &query->questions[0];

        char expected_subdomain[255];
        size_t encoded_len = b32_encode(expected_subdomain, (const char*)(payload + (i * requested_segment)),
                                        requested_segment, true, false);
        size_t dotted_len = slipstream_inline_dotify(expected_subdomain, sizeof expected_subdomain, encoded_len);
        expected_subdomain[dotted_len] = '\0';

        char expected_name[512];
        snprintf(expected_name, sizeof expected_name, "%s.%s.", expected_subdomain, "example.com");
        assert(strcmp(question->name, expected_name) == 0);
    }

    free(encoded_packets);
}

static void test_client_decode_rejects_malformed_packet(void) {
    unsigned char bogus[] = {0xde, 0xad, 0xbe, 0xef};
    unsigned char* decoded = NULL;
    struct sockaddr_storage dummy = {0};

    ssize_t len = client_decode(NULL, NULL, &decoded, bogus, sizeof bogus, &dummy, &dummy);
    assert(len == -1);
    assert(decoded == NULL);
}

static void test_client_decode_returns_zero_for_query_messages(void) {
    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;

    dns_question_t question = {0};
    question.name = "noop.example.com.";
    question.type = RR_TXT;
    question.class = CLASS_IN;

    dns_query_t query = {0};
    query.id = 99;
    query.query = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &question;

    dns_rcode_t rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &query);
    assert(rc == RCODE_OKAY);

    unsigned char* decoded = NULL;
    struct sockaddr_storage dummy = {0};
    ssize_t len = client_decode(NULL, NULL, &decoded, packet_buf, packet_len, &dummy, &dummy);
    assert(len == 0);
    assert(decoded == NULL);
}

static void test_client_decode_respects_rcodes(void) {
    set_client_domain("example.com");

    dns_query_t response = {0};
    response.id = 42;
    response.query = false;
    response.rcode = RCODE_NAME_ERROR;
    response.qdcount = 0;
    response.ancount = 0;
    response.arcount = 0;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t encode_rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &response);
    assert(encode_rc == RCODE_OKAY);

    unsigned char* decoded = NULL;
    struct sockaddr_storage dummy = {0};
    ssize_t len = client_decode(NULL, NULL, &decoded, packet_buf, packet_len, &dummy, &dummy);
    assert(len == 0);
    assert(decoded == NULL);
}

static void test_client_decode_requires_answer_record(void) {
    set_client_domain("example.com");

    dns_question_t question = {0};
    question.name = "response.example.com.";
    question.type = RR_TXT;
    question.class = CLASS_IN;

    dns_query_t response = {0};
    response.id = 44;
    response.query = false;
    response.rcode = RCODE_OKAY;
    response.qdcount = 1;
    response.questions = &question;
    response.ancount = 0;
    response.answers = NULL;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &response);
    assert(rc == RCODE_OKAY);

    unsigned char* decoded = NULL;
    struct sockaddr_storage dummy = {0};
    ssize_t len = client_decode(NULL, NULL, &decoded, packet_buf, packet_len, &dummy, &dummy);
    assert(len == 0);
    assert(decoded == NULL);
}

static void test_client_decode_extracts_payload(void) {
    set_client_domain("example.com");

    const char question_name[] = "payload.example.com.";
    dns_question_t question = {0};
    question.name = (char*)question_name;
    question.type = RR_TXT;
    question.class = CLASS_IN;

    const char payload[] = "response-data";
    dns_txt_t answer_txt = {0};
    answer_txt.name = question.name;
    answer_txt.type = question.type;
    answer_txt.class = question.class;
    answer_txt.ttl = 60;
    answer_txt.text = (char*)payload;
    answer_txt.len = strlen(payload);

    dns_query_t response = {0};
    response.id = 43;
    response.query = false;
    response.rcode = RCODE_OKAY;
    response.qdcount = 1;
    response.questions = &question;
    response.ancount = 1;
    response.answers = (dns_answer_t*)&answer_txt;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t encode_rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &response);
    assert(encode_rc == RCODE_OKAY);

    unsigned char* decoded = NULL;
    struct sockaddr_storage dummy = {0};
    ssize_t len = client_decode(NULL, NULL, &decoded, packet_buf, packet_len, &dummy, &dummy);
    assert(len == (ssize_t)strlen(payload));
    assert(memcmp(decoded, payload, strlen(payload)) == 0);
    free(decoded);
}

static void test_client_decode_rejects_non_txt_answer(void) {
    set_client_domain("example.com");

    const char question_name[] = "payload.example.com.";
    dns_question_t question = {0};
    question.name = (char*)question_name;
    question.type = RR_TXT;
    question.class = CLASS_IN;

    dns_txt_t answer_txt = {0};
    answer_txt.name = question.name;
    answer_txt.type = RR_A;
    answer_txt.class = question.class;
    answer_txt.ttl = 30;
    answer_txt.text = (char*)"ignored";
    answer_txt.len = strlen("ignored");

    dns_query_t response = {0};
    response.id = 45;
    response.query = false;
    response.rcode = RCODE_OKAY;
    response.qdcount = 1;
    response.questions = &question;
    response.ancount = 1;
    response.answers = (dns_answer_t*)&answer_txt;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t encode_rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &response);
    assert(encode_rc == RCODE_OKAY);

    unsigned char* decoded = NULL;
    struct sockaddr_storage dummy = {0};
    ssize_t len = client_decode(NULL, NULL, &decoded, packet_buf, packet_len, &dummy, &dummy);
    assert(len == 0);
    assert(decoded == NULL);
}

static void test_client_decode_rejects_multiple_answers(void) {
    set_client_domain("example.com");

    const char question_name[] = "payload.example.com.";
    dns_question_t question = {0};
    question.name = (char*)question_name;
    question.type = RR_TXT;
    question.class = CLASS_IN;

    const char primary_payload[] = "primary";
    dns_txt_t first_answer = {0};
    first_answer.name = question.name;
    first_answer.type = question.type;
    first_answer.class = question.class;
    first_answer.ttl = 60;
    first_answer.text = (char*)primary_payload;
    first_answer.len = strlen(primary_payload);

    dns_txt_t second_answer = {0};
    second_answer.name = question.name;
    second_answer.type = question.type;
    second_answer.class = question.class;
    second_answer.ttl = 60;
    second_answer.text = "secondary";
    second_answer.len = strlen("secondary");

    dns_answer_t answers[2];
    memcpy(&answers[0], &first_answer, sizeof(dns_txt_t));
    memcpy(&answers[1], &second_answer, sizeof(dns_txt_t));

    dns_query_t response = {0};
    response.id = 46;
    response.query = false;
    response.rcode = RCODE_OKAY;
    response.qdcount = 1;
    response.questions = &question;
    response.ancount = 2;
    response.answers = answers;

    unsigned char packet_buf[MAX_UDP_PACKET_SIZE] = {0};
    size_t packet_len = sizeof packet_buf;
    dns_rcode_t encode_rc = dns_encode((dns_packet_t*)packet_buf, &packet_len, &response);
    assert(encode_rc == RCODE_OKAY);

    unsigned char* decoded = NULL;
    struct sockaddr_storage dummy = {0};
    ssize_t len = client_decode(NULL, NULL, &decoded, packet_buf, packet_len, &dummy, &dummy);
    assert(len == 0);
    assert(decoded == NULL);
}

int main(void) {
    test_client_encode_segment_appends_domain();
    test_client_encode_handles_segmentation();
    test_client_decode_rejects_malformed_packet();
    test_client_decode_returns_zero_for_query_messages();
    test_client_decode_respects_rcodes();
    test_client_decode_requires_answer_record();
    test_client_decode_extracts_payload();
    test_client_decode_rejects_non_txt_answer();
    test_client_decode_rejects_multiple_answers();
    return 0;
}
