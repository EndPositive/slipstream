#include <assert.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "slipstream_slot.h"

int slipstream_packet_loop_(picoquic_network_thread_ctx_t* thread_ctx, picoquic_socket_ctx_t* s_ctx);

static void unexpected_call(const char* func) {
    fprintf(stderr, "unexpected call: %s\n", func);
    abort();
}

void debug_printf(const char* fmt, ...) {
    (void)fmt;
}

static int unexpected_select(picoquic_socket_ctx_t* s_ctx, int nb_sockets, struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest, int* dest_if, unsigned char* received_ecn, uint8_t* buffer, int buffer_max,
    int64_t delta_t, int* is_wake_up_event, picoquic_network_thread_ctx_t* thread_ctx, int* socket_rank) {
    (void)s_ctx;
    (void)nb_sockets;
    (void)addr_from;
    (void)addr_dest;
    (void)dest_if;
    (void)received_ecn;
    (void)buffer;
    (void)buffer_max;
    (void)delta_t;
    (void)is_wake_up_event;
    (void)thread_ctx;
    (void)socket_rank;
    unexpected_call("picoquic_packet_loop_select");
    return -1;
}

static uint64_t mock_current_time_value = 0;
static int64_t mock_wake_delay_value = 0;

static uint64_t default_current_time(void) {
    return mock_current_time_value;
}

static int64_t default_next_wake_delay(picoquic_quic_t* quic, uint64_t now, int64_t delay_max) {
    (void)quic;
    (void)now;
    (void)delay_max;
    return mock_wake_delay_value;
}

static int unexpected_incoming(picoquic_quic_t* quic, uint8_t* bytes, size_t length, struct sockaddr* addr_from,
    struct sockaddr* addr_to, int if_index_to, unsigned char received_ecn, picoquic_cnx_t** first_cnx,
    int* first_path_id, uint64_t current_time) {
    (void)quic;
    (void)bytes;
    (void)length;
    (void)addr_from;
    (void)addr_to;
    (void)if_index_to;
    (void)received_ecn;
    (void)first_cnx;
    (void)first_path_id;
    (void)current_time;
    unexpected_call("picoquic_incoming_packet_ex");
    return -1;
}

static int unexpected_prepare_packet(picoquic_cnx_t* cnx, int path_id_request, uint64_t current_time,
    uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, struct sockaddr_storage* p_addr_to,
    struct sockaddr_storage* p_addr_from, int* if_index, size_t* send_msg_size) {
    (void)cnx;
    (void)path_id_request;
    (void)current_time;
    (void)send_buffer;
    (void)send_buffer_max;
    (void)send_length;
    (void)p_addr_to;
    (void)p_addr_from;
    (void)if_index;
    (void)send_msg_size;
    unexpected_call("picoquic_prepare_packet_ex");
    return -1;
}

static int unexpected_prepare_next_packet(picoquic_quic_t* quic, uint64_t current_time, uint8_t* send_buffer,
    size_t send_buffer_max, size_t* send_length, struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from,
    int* if_index, picoquic_connection_id_t* log_cid, picoquic_cnx_t** p_last_cnx, size_t* send_msg_size) {
    (void)quic;
    (void)current_time;
    (void)send_buffer;
    (void)send_buffer_max;
    (void)send_length;
    (void)p_addr_to;
    (void)p_addr_from;
    (void)if_index;
    (void)log_cid;
    (void)p_last_cnx;
    (void)send_msg_size;
    unexpected_call("picoquic_prepare_next_packet_ex");
    return -1;
}

static int unexpected_sendmsg(SOCKET_TYPE fd, struct sockaddr* addr_dest, struct sockaddr* addr_from, int dest_if,
    const char* bytes, int length, int send_msg_size, int* sock_err) {
    (void)fd;
    (void)addr_dest;
    (void)addr_from;
    (void)dest_if;
    (void)bytes;
    (void)length;
    (void)send_msg_size;
    (void)sock_err;
    unexpected_call("picoquic_sendmsg");
    return -1;
}

static int (*select_impl)(picoquic_socket_ctx_t*, int, struct sockaddr_storage*, struct sockaddr_storage*, int*,
    unsigned char*, uint8_t*, int, int64_t, int*, picoquic_network_thread_ctx_t*, int*) = unexpected_select;
static uint64_t (*current_time_impl)(void) = default_current_time;
static int64_t (*next_wake_delay_impl)(picoquic_quic_t*, uint64_t, int64_t) = default_next_wake_delay;
static int (*incoming_impl)(picoquic_quic_t*, uint8_t*, size_t, struct sockaddr*, struct sockaddr*, int,
    unsigned char, picoquic_cnx_t**, int*, uint64_t) = unexpected_incoming;
static int (*prepare_packet_impl)(picoquic_cnx_t*, int, uint64_t, uint8_t*, size_t, size_t*,
    struct sockaddr_storage*, struct sockaddr_storage*, int*, size_t*) = unexpected_prepare_packet;
static int (*prepare_next_packet_impl)(picoquic_quic_t*, uint64_t, uint8_t*, size_t, size_t*,
    struct sockaddr_storage*, struct sockaddr_storage*, int*, picoquic_connection_id_t*, picoquic_cnx_t**, size_t*)
    = unexpected_prepare_next_packet;
static int (*sendmsg_impl)(SOCKET_TYPE, struct sockaddr*, struct sockaddr*, int, const char*, int, int, int*)
    = unexpected_sendmsg;

static void reset_mocks(void) {
    select_impl = unexpected_select;
    current_time_impl = default_current_time;
    next_wake_delay_impl = default_next_wake_delay;
    incoming_impl = unexpected_incoming;
    prepare_packet_impl = unexpected_prepare_packet;
    prepare_next_packet_impl = unexpected_prepare_next_packet;
    sendmsg_impl = unexpected_sendmsg;
    mock_current_time_value = 0;
    mock_wake_delay_value = 0;
}

int picoquic_packet_loop_select(picoquic_socket_ctx_t* s_ctx, int nb_sockets, struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest, int* dest_if, unsigned char* received_ecn, uint8_t* buffer, int buffer_max,
    int64_t delta_t, int* is_wake_up_event, picoquic_network_thread_ctx_t* thread_ctx, int* socket_rank) {
    return select_impl(s_ctx, nb_sockets, addr_from, addr_dest, dest_if, received_ecn, buffer, buffer_max,
        delta_t, is_wake_up_event, thread_ctx, socket_rank);
}

int picoquic_packet_loop_open_sockets(uint16_t local_port, int local_af, int socket_buffer_size, int nb_server_sockets,
    int do_not_use_gso, picoquic_socket_ctx_t* s_ctx) {
    (void)local_port;
    (void)local_af;
    (void)socket_buffer_size;
    (void)nb_server_sockets;
    (void)do_not_use_gso;
    (void)s_ctx;
    return 1;
}

void picoquic_packet_loop_close_socket(picoquic_socket_ctx_t* s_ctx) {
    (void)s_ctx;
}

uint64_t picoquic_current_time(void) {
    return current_time_impl();
}

int64_t picoquic_get_next_wake_delay(picoquic_quic_t* quic, uint64_t now, int64_t delay_max) {
    return next_wake_delay_impl(quic, now, delay_max);
}

picoquic_cnx_t* picoquic_get_first_cnx(picoquic_quic_t* quic) {
    (void)quic;
    return NULL;
}

picoquic_cnx_t* picoquic_get_next_cnx(picoquic_cnx_t* cnx) {
    (void)cnx;
    return NULL;
}

int picoquic_incoming_packet_ex(picoquic_quic_t* quic, uint8_t* bytes, size_t length, struct sockaddr* addr_from,
    struct sockaddr* addr_to, int if_index_to, unsigned char received_ecn, picoquic_cnx_t** first_cnx,
    int* first_path_id, uint64_t current_time) {
    return incoming_impl(quic, bytes, length, addr_from, addr_to, if_index_to, received_ecn, first_cnx,
        first_path_id, current_time);
}

int picoquic_prepare_packet_ex(picoquic_cnx_t* cnx, int path_id_request, uint64_t current_time, uint8_t* send_buffer,
    size_t send_buffer_max, size_t* send_length, struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from,
    int* if_index, size_t* send_msg_size) {
    return prepare_packet_impl(cnx, path_id_request, current_time, send_buffer, send_buffer_max, send_length,
        p_addr_to, p_addr_from, if_index, send_msg_size);
}

int picoquic_prepare_next_packet_ex(picoquic_quic_t* quic, uint64_t current_time, uint8_t* send_buffer,
    size_t send_buffer_max, size_t* send_length, struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from,
    int* if_index, picoquic_connection_id_t* log_cid, picoquic_cnx_t** p_last_cnx, size_t* send_msg_size) {
    return prepare_next_packet_impl(quic, current_time, send_buffer, send_buffer_max, send_length,
        p_addr_to, p_addr_from, if_index, log_cid, p_last_cnx, send_msg_size);
}

int picoquic_sendmsg(SOCKET_TYPE fd, struct sockaddr* addr_dest, struct sockaddr* addr_from, int dest_if,
    const char* bytes, int length, int send_msg_size, int* sock_err) {
    return sendmsg_impl(fd, addr_dest, addr_from, dest_if, bytes, length, send_msg_size, sock_err);
}

typedef struct {
    int before_select_calls;
    int wake_up_calls;
    int wake_up_return;
} callback_state_t;

static int mock_loop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum mode, void* ctx, void* arg) {
    (void)quic;
    (void)arg;
    callback_state_t* state = (callback_state_t*)ctx;

    switch (mode) {
    case picoquic_packet_loop_before_select:
        state->before_select_calls++;
        return 0;
    case picoquic_packet_loop_wake_up:
        state->wake_up_calls++;
        if (state->wake_up_return != 0) {
            return state->wake_up_return;
        }
        return 0;
    default:
        return 0;
    }
}

static ssize_t decode_should_not_run(void* slot_p, void* callback_ctx, unsigned char** dest_buf,
    const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage* peer_addr,
    struct sockaddr_storage* local_addr) {
    (void)slot_p;
    (void)callback_ctx;
    (void)dest_buf;
    (void)src_buf;
    (void)src_buf_len;
    (void)peer_addr;
    (void)local_addr;
    unexpected_call("decode should not run");
    return -1;
}

static ssize_t encode_should_not_run(void* slot_p, void* callback_ctx, unsigned char** dest_buf,
    const unsigned char* src_buf, size_t src_buf_len, size_t* segment_len, struct sockaddr_storage* peer_addr,
    struct sockaddr_storage* local_addr) {
    (void)slot_p;
    (void)callback_ctx;
    (void)dest_buf;
    (void)src_buf;
    (void)src_buf_len;
    (void)segment_len;
    (void)peer_addr;
    (void)local_addr;
    unexpected_call("encode should not run");
    return -1;
}

static int select_returns_wakeup_event(picoquic_socket_ctx_t* s_ctx, int nb_sockets, struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest, int* dest_if, unsigned char* received_ecn, uint8_t* buffer, int buffer_max,
    int64_t delta_t, int* is_wake_up_event, picoquic_network_thread_ctx_t* thread_ctx, int* socket_rank) {
    (void)s_ctx;
    (void)nb_sockets;
    (void)addr_from;
    (void)addr_dest;
    (void)dest_if;
    (void)received_ecn;
    (void)buffer;
    (void)buffer_max;
    (void)delta_t;
    (void)thread_ctx;
    (void)socket_rank;
    *is_wake_up_event = 1;
    return 0;
}

static int select_returns_16_bytes(picoquic_socket_ctx_t* s_ctx, int nb_sockets, struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest, int* dest_if, unsigned char* received_ecn, uint8_t* buffer, int buffer_max,
    int64_t delta_t, int* is_wake_up_event, picoquic_network_thread_ctx_t* thread_ctx, int* socket_rank) {
    (void)s_ctx;
    (void)nb_sockets;
    (void)addr_from;
    (void)addr_dest;
    (void)dest_if;
    (void)received_ecn;
    (void)buffer;
    (void)buffer_max;
    (void)delta_t;
    (void)thread_ctx;
    (void)socket_rank;
    *is_wake_up_event = 0;
    return 16;
}

static int select_returns_32_bytes(picoquic_socket_ctx_t* s_ctx, int nb_sockets, struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest, int* dest_if, unsigned char* received_ecn, uint8_t* buffer, int buffer_max,
    int64_t delta_t, int* is_wake_up_event, picoquic_network_thread_ctx_t* thread_ctx, int* socket_rank) {
    (void)s_ctx;
    (void)nb_sockets;
    (void)addr_from;
    (void)addr_dest;
    (void)dest_if;
    (void)received_ecn;
    (void)buffer;
    (void)buffer_max;
    (void)delta_t;
    (void)thread_ctx;
    (void)socket_rank;
    *is_wake_up_event = 0;
    return 32;
}

static int select_returns_24_bytes(picoquic_socket_ctx_t* s_ctx, int nb_sockets, struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest, int* dest_if, unsigned char* received_ecn, uint8_t* buffer, int buffer_max,
    int64_t delta_t, int* is_wake_up_event, picoquic_network_thread_ctx_t* thread_ctx, int* socket_rank) {
    (void)s_ctx;
    (void)nb_sockets;
    (void)addr_from;
    (void)addr_dest;
    (void)dest_if;
    (void)received_ecn;
    (void)buffer;
    (void)buffer_max;
    (void)delta_t;
    (void)thread_ctx;
    (void)socket_rank;
    *is_wake_up_event = 0;
    return 24;
}

static ssize_t decode_returns_error(void* slot_p, void* callback_ctx, unsigned char** dest_buf,
    const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage* peer_addr,
    struct sockaddr_storage* local_addr) {
    (void)slot_p;
    (void)callback_ctx;
    (void)dest_buf;
    (void)src_buf;
    (void)src_buf_len;
    (void)peer_addr;
    (void)local_addr;
    return -777;
}

static ssize_t decode_returns_payload(void* slot_p, void* callback_ctx, unsigned char** dest_buf,
    const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage* peer_addr,
    struct sockaddr_storage* local_addr) {
    (void)callback_ctx;
    (void)peer_addr;
    (void)local_addr;
    slot_t* slot = (slot_t*)slot_p;
    *dest_buf = (unsigned char*)malloc(8);
    memset(*dest_buf, 0xAB, 8);
    slot->error = RCODE_OKAY;
    (void)src_buf;
    (void)src_buf_len;
    return 8;
}

static ssize_t decode_returns_payload_for_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf,
    const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage* peer_addr,
    struct sockaddr_storage* local_addr) {
    (void)callback_ctx;
    (void)src_buf;
    (void)src_buf_len;
    (void)peer_addr;
    (void)local_addr;
    slot_t* slot = (slot_t*)slot_p;
    *dest_buf = (unsigned char*)malloc(12);
    memset(*dest_buf, 0, 12);
    slot->error = RCODE_OKAY;
    return 12;
}

static int incoming_returns_error(picoquic_quic_t* quic, uint8_t* bytes, size_t length, struct sockaddr* addr_from,
    struct sockaddr* addr_to, int if_index_to, unsigned char received_ecn, picoquic_cnx_t** first_cnx,
    int* first_path_id, uint64_t current_time) {
    (void)quic;
    (void)bytes;
    (void)length;
    (void)addr_from;
    (void)addr_to;
    (void)if_index_to;
    (void)received_ecn;
    (void)first_cnx;
    (void)first_path_id;
    (void)current_time;
    return -199;
}

static picoquic_cnx_t dummy_cnx = {0};

static int incoming_returns_success(picoquic_quic_t* quic, uint8_t* bytes, size_t length, struct sockaddr* addr_from,
    struct sockaddr* addr_to, int if_index_to, unsigned char received_ecn, picoquic_cnx_t** first_cnx,
    int* first_path_id, uint64_t current_time) {
    (void)quic;
    (void)bytes;
    (void)length;
    (void)addr_from;
    (void)addr_to;
    (void)if_index_to;
    (void)received_ecn;
    (void)current_time;
    *first_cnx = &dummy_cnx;
    *first_path_id = 7;
    return 0;
}

static int prepare_packet_sets_length(picoquic_cnx_t* cnx, int path_id_request, uint64_t current_time,
    uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, struct sockaddr_storage* p_addr_to,
    struct sockaddr_storage* p_addr_from, int* if_index, size_t* send_msg_size) {
    (void)cnx;
    (void)path_id_request;
    (void)current_time;
    (void)send_buffer;
    (void)send_buffer_max;
    (void)p_addr_to;
    (void)p_addr_from;
    (void)if_index;
    (void)send_msg_size;
    *send_length = 20;
    return 0;
}

static ssize_t encode_returns_shorter_segment(void* slot_p, void* callback_ctx, unsigned char** dest_buf,
    const unsigned char* src_buf, size_t src_buf_len, size_t* segment_len, struct sockaddr_storage* peer_addr,
    struct sockaddr_storage* local_addr) {
    (void)slot_p;
    (void)callback_ctx;
    (void)src_buf;
    (void)src_buf_len;
    (void)peer_addr;
    (void)local_addr;
    *segment_len = 10;
    *dest_buf = (unsigned char*)malloc(8);
    memset(*dest_buf, 0, 8);
    return 8;
}

static void test_slipstream_packet_loop_propagates_wakeup_error(void) {
    reset_mocks();

    select_impl = select_returns_wakeup_event;

    callback_state_t cb_state = {0};
    cb_state.wake_up_return = -42;

    picoquic_packet_loop_param_t param = {0};
    param.decode = decode_should_not_run;
    param.encode = encode_should_not_run;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.param = &param;
    thread_ctx.loop_callback = mock_loop_callback;
    thread_ctx.loop_callback_ctx = &cb_state;

    picoquic_socket_ctx_t socket_ctx = {0};

    int rc = slipstream_packet_loop_(&thread_ctx, &socket_ctx);
    assert(rc == -42);
    assert(cb_state.before_select_calls == 1);
    assert(cb_state.wake_up_calls == 1);
}

static void test_slipstream_packet_loop_returns_decode_error(void) {
    reset_mocks();

    select_impl = select_returns_16_bytes;

    callback_state_t cb_state = {0};

    picoquic_packet_loop_param_t param = {0};
    param.decode = decode_returns_error;
    param.encode = encode_should_not_run;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.param = &param;
    thread_ctx.loop_callback = mock_loop_callback;
    thread_ctx.loop_callback_ctx = &cb_state;

    picoquic_socket_ctx_t socket_ctx = {0};

    int rc = slipstream_packet_loop_(&thread_ctx, &socket_ctx);
    assert(rc == -777);
    assert(cb_state.before_select_calls == 1);
    assert(cb_state.wake_up_calls == 0);
}

static void test_slipstream_packet_loop_incoming_error(void) {
    reset_mocks();

    select_impl = select_returns_32_bytes;
    incoming_impl = incoming_returns_error;

    callback_state_t cb_state = {0};

    picoquic_packet_loop_param_t param = {0};
    param.decode = decode_returns_payload;
    param.encode = encode_should_not_run;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.param = &param;
    thread_ctx.loop_callback = mock_loop_callback;
    thread_ctx.loop_callback_ctx = &cb_state;

    picoquic_socket_ctx_t socket_ctx = {0};

    int rc = slipstream_packet_loop_(&thread_ctx, &socket_ctx);
    assert(rc == -199);
    assert(cb_state.before_select_calls == 1);
}

static void test_slipstream_packet_loop_catches_short_encode(void) {
    reset_mocks();

    select_impl = select_returns_24_bytes;
    incoming_impl = incoming_returns_success;
    prepare_packet_impl = prepare_packet_sets_length;

    picoquic_packet_loop_param_t param = {0};
    param.decode = decode_returns_payload_for_encode;
    param.encode = encode_returns_shorter_segment;

    callback_state_t cb_state = {0};

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.param = &param;
    thread_ctx.loop_callback = mock_loop_callback;
    thread_ctx.loop_callback_ctx = &cb_state;

    picoquic_socket_ctx_t socket_ctx = {0};

    int rc = slipstream_packet_loop_(&thread_ctx, &socket_ctx);
    assert(rc == -1);
    assert(cb_state.before_select_calls == 1);
}

int main(void) {
    test_slipstream_packet_loop_propagates_wakeup_error();
    test_slipstream_packet_loop_returns_decode_error();
    test_slipstream_packet_loop_incoming_error();
    test_slipstream_packet_loop_catches_short_encode();
    return 0;
}
