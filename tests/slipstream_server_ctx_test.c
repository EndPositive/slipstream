#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "slipstream.h"

typedef struct st_slipstream_server_stream_ctx_t {
    struct st_slipstream_server_stream_ctx_t* next_stream;
    struct st_slipstream_server_stream_ctx_t* previous_stream;
    int fd;
    int pipefd[2];
    uint64_t stream_id;
    volatile sig_atomic_t set_active;
} slipstream_server_stream_ctx_t;

typedef struct st_slipstream_server_ctx_t {
    picoquic_cnx_t* cnx;
    slipstream_server_stream_ctx_t* first_stream;
    picoquic_network_thread_ctx_t* thread_ctx;
    struct sockaddr_storage upstream_addr;
    struct st_slipstream_server_ctx_t* prev_ctx;
    struct st_slipstream_server_ctx_t* next_ctx;
    uint64_t shutdown_started_at;
    bool shutdown_forced_logged;
} slipstream_server_ctx_t;

typedef struct st_slipstream_server_poller_args {
    int fd;
    picoquic_cnx_t* cnx;
    slipstream_server_ctx_t* server_ctx;
    slipstream_server_stream_ctx_t* stream_ctx;
} slipstream_server_poller_args;

slipstream_server_stream_ctx_t* slipstream_server_create_stream_ctx(slipstream_server_ctx_t* server_ctx, uint64_t stream_id);
void slipstream_server_mark_active_pass(slipstream_server_ctx_t* server_ctx);
void test_slipstream_server_free_stream_context(slipstream_server_ctx_t* server_ctx, slipstream_server_stream_ctx_t* stream_ctx);
void test_slipstream_server_free_context(slipstream_server_ctx_t* server_ctx);

extern void reset_server_ctx_test_state(void);
extern bool test_pipe_fail;
extern bool test_socket_fail;
extern int test_pipe_calls;
extern int test_socket_calls;
extern int test_close_calls;
extern int test_closed_fds[8];
extern int test_mark_active_calls;
extern uint64_t test_mark_active_stream_ids[8];
extern void* test_mark_active_stream_ctx[8];
extern int test_picoquic_reset_stream_calls;
extern uint64_t test_picoquic_reset_stream_ids[8];
extern uint64_t test_picoquic_reset_stream_errors[8];
extern int test_picoquic_set_app_stream_ctx_calls;
extern void* test_picoquic_set_app_stream_ctx_ctx[8];
extern int test_picoquic_set_app_stream_ctx_result;
extern int test_picoquic_unlink_app_stream_ctx_calls;
extern uint64_t test_picoquic_unlink_stream_ids[8];
extern int test_picoquic_set_callback_calls;
extern void* test_picoquic_last_callback_ctx;
extern int test_picoquic_close_calls;
extern uint64_t test_picoquic_close_codes[8];
extern int test_picoquic_wake_up_calls;
extern picoquic_network_thread_ctx_t* test_picoquic_last_thread_ctx;
extern void* test_default_callback_ctx;
extern picoquic_quic_t test_quic_ctx;
extern int test_pthread_create_calls;
extern int test_pthread_detach_calls;
extern int test_write_calls;
extern int test_write_last_fd;
extern size_t test_write_last_count;
extern uint8_t test_write_buffer[256];
extern int test_write_failures_remaining;
extern int test_write_errno;
extern ssize_t test_write_return_override;
extern int test_ioctl_calls;
extern int test_ioctl_should_fail;
extern int test_ioctl_errno;
extern int test_ioctl_last_fd;
extern unsigned long test_ioctl_last_request;
extern int test_ioctl_fionread_value;
extern int test_ioctl_return_value;
extern int test_recv_calls;
extern int test_recv_last_fd;
extern size_t test_recv_last_len;
extern int test_recv_last_flags;
extern ssize_t test_recv_return_value;
extern int test_recv_errno;
extern uint8_t test_recv_fill_byte;
extern int test_picoquic_provide_stream_data_buffer_calls;
extern size_t test_picoquic_provide_stream_data_buffer_last_nb;
extern int test_picoquic_provide_stream_data_buffer_last_fin;
extern int test_picoquic_provide_stream_data_buffer_last_active;
extern void* test_picoquic_provide_stream_data_buffer_last_ctx;
extern uint8_t test_picoquic_provide_stream_data_buffer_storage[512];
extern void* test_pthread_last_arg;
extern bool test_skip_arg_free_on_success;

int slipstream_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

static picoquic_cnx_t mock_cnx = {0};

static void test_create_stream_ctx_success(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(&server_ctx, 77);
    assert(stream_ctx != NULL);
    assert(server_ctx.first_stream == stream_ctx);
    assert(stream_ctx->stream_id == 77);
    assert(stream_ctx->next_stream == NULL);
    assert(stream_ctx->previous_stream == NULL);
    assert(test_pipe_calls == 1);
    assert(test_socket_calls == 1);
    assert(test_close_calls == 0);
    assert(stream_ctx->pipefd[0] != stream_ctx->pipefd[1]);
    assert(stream_ctx->fd >= stream_ctx->pipefd[1]);

    /* cleanup */
    server_ctx.first_stream = NULL;
    free(stream_ctx);
}

static void test_create_stream_ctx_pipe_failure(void) {
    reset_server_ctx_test_state();
    test_pipe_fail = true;

    slipstream_server_ctx_t server_ctx = {0};

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(&server_ctx, 42);
    assert(stream_ctx == NULL);
    assert(server_ctx.first_stream == NULL);
    assert(test_pipe_calls == 1);
    assert(test_socket_calls == 0);
    assert(test_close_calls == 0);
}

static void test_create_stream_ctx_socket_failure_closes_pipe(void) {
    reset_server_ctx_test_state();
    test_socket_fail = true;

    slipstream_server_ctx_t server_ctx = {0};

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(&server_ctx, 55);
    assert(stream_ctx == NULL);
    assert(server_ctx.first_stream == NULL);
    assert(test_pipe_calls == 1);
    assert(test_socket_calls == 1);
    assert(test_close_calls == 2);
    assert(test_closed_fds[0] == 100);
    assert(test_closed_fds[1] == 101);
}

static void test_mark_active_pass_triggers_callbacks(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    slipstream_server_stream_ctx_t* first = slipstream_server_create_stream_ctx(&server_ctx, 10);
    assert(first != NULL);
    slipstream_server_stream_ctx_t* second = slipstream_server_create_stream_ctx(&server_ctx, 11);
    assert(second != NULL);

    assert(server_ctx.first_stream == second);
    assert(second->next_stream == first);
    assert(first->previous_stream == second);

    first->set_active = 1;
    second->set_active = 1;

    slipstream_server_mark_active_pass(&server_ctx);

    assert(test_mark_active_calls == 2);
    assert(test_mark_active_stream_ids[0] == 11);
    assert(test_mark_active_stream_ids[1] == 10);
    assert(test_mark_active_stream_ctx[0] == second);
    assert(test_mark_active_stream_ctx[1] == first);
    assert(first->set_active == 0);
    assert(second->set_active == 0);

    server_ctx.first_stream = NULL;
    free(second);
    free(first);
}

static void test_free_stream_ctx_unlinks_middle(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    slipstream_server_stream_ctx_t* tail = slipstream_server_create_stream_ctx(&server_ctx, 1);
    assert(tail != NULL);
    slipstream_server_stream_ctx_t* middle = slipstream_server_create_stream_ctx(&server_ctx, 2);
    assert(middle != NULL);
    slipstream_server_stream_ctx_t* head = slipstream_server_create_stream_ctx(&server_ctx, 3);
    assert(head != NULL);

    assert(server_ctx.first_stream == head);
    assert(head->next_stream == middle);
    assert(middle->previous_stream == head);
    assert(middle->next_stream == tail);
    assert(tail->previous_stream == middle);

    int middle_fd = middle->fd;
    test_slipstream_server_free_stream_context(&server_ctx, middle);

    assert(server_ctx.first_stream == head);
    assert(head->next_stream == tail);
    assert(tail->previous_stream == head);
    assert(test_close_calls == 1);
    assert(test_closed_fds[0] == middle_fd);

    test_slipstream_server_free_stream_context(&server_ctx, head);
    test_slipstream_server_free_stream_context(&server_ctx, tail);
}

static void test_free_context_releases_all_streams(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t prev_ctx = {0};
    slipstream_server_ctx_t next_ctx = {0};

    slipstream_server_ctx_t* target = (slipstream_server_ctx_t*)calloc(1, sizeof(slipstream_server_ctx_t));
    assert(target != NULL);
    target->cnx = &mock_cnx;
    target->prev_ctx = &prev_ctx;
    target->next_ctx = &next_ctx;

    prev_ctx.next_ctx = target;
    next_ctx.prev_ctx = target;

    slipstream_server_stream_ctx_t* first = slipstream_server_create_stream_ctx(target, 1001);
    assert(first != NULL);
    slipstream_server_stream_ctx_t* second = slipstream_server_create_stream_ctx(target, 1002);
    assert(second != NULL);

    int second_fd = second->fd;
    int first_fd = first->fd;

    test_slipstream_server_free_context(target);

    assert(prev_ctx.next_ctx == &next_ctx);
    assert(next_ctx.prev_ctx == &prev_ctx);
    assert(test_close_calls == 2);
    assert(test_closed_fds[0] == second_fd);
    assert(test_closed_fds[1] == first_fd);
}

static void test_callback_stream_reset_cleans_stream(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(&server_ctx, 73);
    assert(stream_ctx != NULL);

    int original_fd = stream_ctx->fd;
    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    int rc = slipstream_server_callback(&cnx, 73, NULL, 0, picoquic_callback_stream_reset, &server_ctx, stream_ctx);
    assert(rc == 0);

    assert(test_picoquic_reset_stream_calls == 1);
    assert(test_picoquic_reset_stream_ids[0] == 73);
    assert(test_picoquic_reset_stream_errors[0] == SLIPSTREAM_FILE_CANCEL_ERROR);
    assert(test_close_calls == 1);
    assert(test_closed_fds[0] == original_fd);
    assert(server_ctx.first_stream == NULL);
}

static void test_callback_stop_sending_triggers_double_reset(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(&server_ctx, 88);
    assert(stream_ctx != NULL);

    int original_fd = stream_ctx->fd;
    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    int rc = slipstream_server_callback(&cnx, 88, NULL, 0, picoquic_callback_stop_sending, &server_ctx, stream_ctx);
    assert(rc == 0);

    assert(test_picoquic_reset_stream_calls == 2);
    assert(test_picoquic_reset_stream_ids[0] == 88);
    assert(test_picoquic_reset_stream_errors[0] == 0);
    assert(test_picoquic_reset_stream_ids[1] == 88);
    assert(test_picoquic_reset_stream_errors[1] == SLIPSTREAM_FILE_CANCEL_ERROR);
    assert(test_close_calls == 1);
    assert(test_closed_fds[0] == original_fd);
    assert(server_ctx.first_stream == NULL);
}

static void test_callback_close_releases_context(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t default_ctx = {0};
    slipstream_server_ctx_t* server_ctx = calloc(1, sizeof(*server_ctx));
    assert(server_ctx != NULL);
    server_ctx->cnx = &mock_cnx;
    server_ctx->prev_ctx = &default_ctx;
    default_ctx.next_ctx = server_ctx;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    server_ctx->thread_ctx = &thread_ctx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(server_ctx, 91);
    assert(stream_ctx != NULL);

    int stream_fd = stream_ctx->fd;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    test_default_callback_ctx = &default_ctx;

    int rc = slipstream_server_callback(&cnx, 91, NULL, 0, picoquic_callback_close, server_ctx, stream_ctx);
    assert(rc == 0);

    assert(test_picoquic_set_callback_calls == 1);
    assert(test_picoquic_last_callback_ctx == NULL);
    assert(test_picoquic_close_calls == 1);
    assert(test_picoquic_close_codes[0] == 0);
    assert(test_picoquic_wake_up_calls == 1);
    assert(test_picoquic_last_thread_ctx == &thread_ctx);
    assert(test_close_calls >= 1);
    assert(test_closed_fds[0] == stream_fd);
    assert(default_ctx.next_ctx == NULL);
}

static void test_callback_stateless_reset_releases_context(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t default_ctx = {0};
    slipstream_server_ctx_t* server_ctx = calloc(1, sizeof(*server_ctx));
    assert(server_ctx != NULL);
    server_ctx->cnx = &mock_cnx;
    server_ctx->prev_ctx = &default_ctx;
    default_ctx.next_ctx = server_ctx;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    server_ctx->thread_ctx = &thread_ctx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(server_ctx, 92);
    assert(stream_ctx != NULL);
    int stream_fd = stream_ctx->fd;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    test_default_callback_ctx = &default_ctx;

    int rc = slipstream_server_callback(&cnx, 92, NULL, 0,
        picoquic_callback_stateless_reset, server_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_picoquic_set_callback_calls == 1);
    assert(test_picoquic_last_callback_ctx == NULL);
    assert(test_picoquic_close_calls == 1);
    assert(test_picoquic_close_codes[0] == 0);
    assert(test_picoquic_wake_up_calls == 1);
    assert(test_picoquic_last_thread_ctx == &thread_ctx);
    assert(test_close_calls >= 1);
    assert(test_closed_fds[0] == stream_fd);
    assert(default_ctx.next_ctx == NULL);
}

static void test_callback_application_close_releases_context(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t default_ctx = {0};
    slipstream_server_ctx_t* server_ctx = calloc(1, sizeof(*server_ctx));
    assert(server_ctx != NULL);
    server_ctx->cnx = &mock_cnx;
    server_ctx->prev_ctx = &default_ctx;
    default_ctx.next_ctx = server_ctx;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    server_ctx->thread_ctx = &thread_ctx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(server_ctx, 93);
    assert(stream_ctx != NULL);
    int stream_fd = stream_ctx->fd;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    test_default_callback_ctx = &default_ctx;

    int rc = slipstream_server_callback(&cnx, 93, NULL, 0,
        picoquic_callback_application_close, server_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_picoquic_set_callback_calls == 1);
    assert(test_picoquic_last_callback_ctx == NULL);
    assert(test_picoquic_close_calls == 1);
    assert(test_picoquic_close_codes[0] == 0);
    assert(test_picoquic_wake_up_calls == 1);
    assert(test_picoquic_last_thread_ctx == &thread_ctx);
    assert(test_close_calls >= 1);
    assert(test_closed_fds[0] == stream_fd);
    assert(default_ctx.next_ctx == NULL);
}

static void test_callback_stream_data_happy_path(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    server_ctx.thread_ctx = &thread_ctx;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};

    int rc = slipstream_server_callback(&cnx, 321, payload, sizeof(payload),
        picoquic_callback_stream_data, &server_ctx, NULL);
    assert(rc == 0);

    assert(test_pthread_create_calls == 1);
    assert(test_picoquic_set_app_stream_ctx_calls == 1);
    assert(test_write_calls == 1);
    assert(test_write_last_count == sizeof(payload));
    for (size_t i = 0; i < sizeof(payload); ++i) {
        assert(test_write_buffer[i] == payload[i]);
    }
    assert(server_ctx.first_stream != NULL);
    slipstream_server_stream_ctx_t* stream_ctx = server_ctx.first_stream;
    assert(stream_ctx->stream_id == 321);
    assert(test_write_last_fd == stream_ctx->pipefd[1]);
    assert(test_picoquic_reset_stream_calls == 0);
    assert(test_pthread_detach_calls == 1);

    rc = slipstream_server_callback(&cnx, 321, NULL, 0,
        picoquic_callback_stream_fin, &server_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_picoquic_unlink_app_stream_ctx_calls == 1);

    test_slipstream_server_free_stream_context(&server_ctx, stream_ctx);
}

static void test_callback_stream_data_set_app_ctx_failure_resets(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    uint8_t payload = 0x7c;
    test_picoquic_set_app_stream_ctx_result = -1;

    int rc = slipstream_server_callback(&cnx, 400, &payload, 1,
        picoquic_callback_stream_data, &server_ctx, NULL);
    assert(rc == 0);
    assert(test_picoquic_set_app_stream_ctx_calls == 1);
    assert(test_picoquic_reset_stream_calls == 1);
    assert(test_picoquic_reset_stream_errors[0] == SLIPSTREAM_INTERNAL_ERROR);
    assert(server_ctx.first_stream != NULL);

    slipstream_server_stream_ctx_t* stream_ctx = server_ctx.first_stream;
    test_slipstream_server_free_stream_context(&server_ctx, stream_ctx);
}

static void test_callback_stream_data_write_epipe_resets(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    server_ctx.thread_ctx = &thread_ctx;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    uint8_t payload[] = {0x01, 0x02};
    test_write_failures_remaining = 1;
    test_write_return_override = -1;
    test_write_errno = EPIPE;

    int rc = slipstream_server_callback(&cnx, 401, payload, sizeof(payload),
        picoquic_callback_stream_data, &server_ctx, NULL);
    assert(rc == 0);
    assert(test_write_calls == 1);
    assert(test_picoquic_reset_stream_calls == 1);
    assert(test_picoquic_reset_stream_errors[0] == SLIPSTREAM_FILE_CANCEL_ERROR);

    slipstream_server_stream_ctx_t* stream_ctx = server_ctx.first_stream;
    assert(stream_ctx != NULL);
    test_slipstream_server_free_stream_context(&server_ctx, stream_ctx);
}

static void test_callback_prepare_to_send_reads_available(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(&server_ctx, 501);
    assert(stream_ctx != NULL);

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    test_ioctl_fionread_value = 12;
    test_recv_return_value = 12;
    test_recv_fill_byte = 0x42;

    uint8_t buffer[32] = {0};
    int rc = slipstream_server_callback(&cnx, 501, buffer, sizeof(buffer),
        picoquic_callback_prepare_to_send, &server_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_ioctl_calls == 1);
    assert(test_ioctl_last_fd == stream_ctx->fd);
    assert(test_picoquic_provide_stream_data_buffer_calls == 1);
    assert(test_picoquic_provide_stream_data_buffer_last_nb == 12);
    assert(test_picoquic_provide_stream_data_buffer_last_ctx == buffer);
    assert(test_recv_calls == 1);
    assert(test_recv_last_fd == stream_ctx->fd);
    assert(test_picoquic_reset_stream_calls == 0);

    test_slipstream_server_free_stream_context(&server_ctx, stream_ctx);
}

static void test_callback_prepare_to_send_eagain_triggers_poller(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;
    picoquic_network_thread_ctx_t thread_ctx = {0};
    server_ctx.thread_ctx = &thread_ctx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(&server_ctx, 502);
    assert(stream_ctx != NULL);
    stream_ctx->stream_id = 502;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    test_ioctl_fionread_value = 0;
    test_recv_return_value = -1;
    test_recv_errno = EAGAIN;
    test_skip_arg_free_on_success = true;

    uint8_t buffer[16] = {0};
    int rc = slipstream_server_callback(&cnx, 502, buffer, sizeof(buffer),
        picoquic_callback_prepare_to_send, &server_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_picoquic_provide_stream_data_buffer_calls == 1);
    assert(test_picoquic_provide_stream_data_buffer_last_nb == 0);
    assert(test_pthread_create_calls == 1);
    assert(test_pthread_detach_calls == 1);
    assert(test_picoquic_reset_stream_calls == 0);
    assert(test_picoquic_wake_up_calls == 0);
    assert(test_pthread_last_arg != NULL);
    slipstream_server_poller_args* args = (slipstream_server_poller_args*)test_pthread_last_arg;
    assert(args->fd == stream_ctx->fd);
    assert(args->server_ctx == &server_ctx);
    assert(args->stream_ctx == stream_ctx);

    free(test_pthread_last_arg);
    test_pthread_last_arg = NULL;
    test_skip_arg_free_on_success = false;

    test_slipstream_server_free_stream_context(&server_ctx, stream_ctx);
}

static void test_callback_prepare_to_send_recv_zero_resets(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;

    slipstream_server_stream_ctx_t* stream_ctx = slipstream_server_create_stream_ctx(&server_ctx, 503);
    assert(stream_ctx != NULL);
    stream_ctx->stream_id = 503;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    test_ioctl_fionread_value = 8;
    test_recv_return_value = 0;

    uint8_t buffer[16] = {0};
    int rc = slipstream_server_callback(&cnx, 503, buffer, sizeof(buffer),
        picoquic_callback_prepare_to_send, &server_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_recv_calls == 1);
    assert(test_picoquic_reset_stream_calls == 1);
    assert(test_picoquic_reset_stream_errors[0] == SLIPSTREAM_FILE_CANCEL_ERROR);

    test_slipstream_server_free_stream_context(&server_ctx, stream_ctx);
}

static void test_callback_ignores_datagram_and_path_events(void) {
    const picoquic_call_back_event_t events[] = {
        picoquic_callback_stream_gap,
        picoquic_callback_datagram,
        picoquic_callback_prepare_datagram,
        picoquic_callback_datagram_acked,
        picoquic_callback_datagram_lost,
        picoquic_callback_datagram_spurious,
        picoquic_callback_path_available,
        picoquic_callback_path_suspended,
        picoquic_callback_path_deleted,
        picoquic_callback_path_quality_changed,
        picoquic_callback_path_address_observed,
        picoquic_callback_pacing_changed,
        picoquic_callback_version_negotiation,
        picoquic_callback_request_alpn_list,
        picoquic_callback_set_alpn,
        picoquic_callback_app_wakeup
    };

    for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
        reset_server_ctx_test_state();

        slipstream_server_ctx_t server_ctx = {0};
        server_ctx.cnx = &mock_cnx;
        picoquic_network_thread_ctx_t thread_ctx = {0};
        server_ctx.thread_ctx = &thread_ctx;

        picoquic_cnx_t cnx = {0};
        cnx.quic = &test_quic_ctx;

        int rc = slipstream_server_callback(&cnx, 800 + (uint64_t)i, NULL, 0,
            events[i], &server_ctx, NULL);
        assert(rc == 0);
        assert(test_picoquic_reset_stream_calls == 0);
        assert(test_picoquic_set_callback_calls == 0);
        assert(test_picoquic_close_calls == 0);
        assert(test_picoquic_wake_up_calls == 0);
        assert(server_ctx.first_stream == NULL);
    }
}

static void test_callback_almost_ready_is_noop(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;
    picoquic_network_thread_ctx_t thread_ctx = {0};
    server_ctx.thread_ctx = &thread_ctx;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    int rc = slipstream_server_callback(&cnx, 600, NULL, 0,
        picoquic_callback_almost_ready, &server_ctx, NULL);
    assert(rc == 0);
    assert(test_picoquic_reset_stream_calls == 0);
    assert(server_ctx.first_stream == NULL);
}

static void test_callback_ready_is_noop(void) {
    reset_server_ctx_test_state();

    slipstream_server_ctx_t server_ctx = {0};
    server_ctx.cnx = &mock_cnx;
    picoquic_network_thread_ctx_t thread_ctx = {0};
    server_ctx.thread_ctx = &thread_ctx;

    picoquic_cnx_t cnx = {0};
    cnx.quic = &test_quic_ctx;

    int rc = slipstream_server_callback(&cnx, 601, NULL, 0,
        picoquic_callback_ready, &server_ctx, NULL);
    assert(rc == 0);
    assert(test_picoquic_reset_stream_calls == 0);
    assert(server_ctx.first_stream == NULL);
}

int main(void) {
    test_create_stream_ctx_success();
    test_create_stream_ctx_pipe_failure();
    test_create_stream_ctx_socket_failure_closes_pipe();
    test_mark_active_pass_triggers_callbacks();
    test_free_stream_ctx_unlinks_middle();
    test_free_context_releases_all_streams();
    test_callback_stream_reset_cleans_stream();
    test_callback_stop_sending_triggers_double_reset();
    test_callback_close_releases_context();
    test_callback_stateless_reset_releases_context();
    test_callback_application_close_releases_context();
    test_callback_stream_data_happy_path();
    test_callback_stream_data_set_app_ctx_failure_resets();
    test_callback_stream_data_write_epipe_resets();
    test_callback_prepare_to_send_reads_available();
    test_callback_prepare_to_send_eagain_triggers_poller();
    test_callback_prepare_to_send_recv_zero_resets();
    test_callback_ignores_datagram_and_path_events();
    test_callback_almost_ready_is_noop();
    test_callback_ready_is_noop();
    return 0;
}
