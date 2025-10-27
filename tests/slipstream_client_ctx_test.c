#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "slipstream_slot.h"
#include "slipstream.h"

typedef struct st_slipstream_client_stream_ctx_t {
    struct st_slipstream_client_stream_ctx_t* next_stream;
    struct st_slipstream_client_stream_ctx_t* previous_stream;
    int fd;
    uint64_t stream_id;
    volatile sig_atomic_t set_active;
} slipstream_client_stream_ctx_t;

typedef struct st_slipstream_client_ctx_t {
    picoquic_cnx_t* cnx;
    slipstream_client_stream_ctx_t* first_stream;
    picoquic_network_thread_ctx_t* thread_ctx;
    address_t* server_addresses;
    size_t server_address_count;
    bool ready;
    bool closed;
    int listen_sock;
} slipstream_client_ctx_t;

slipstream_client_stream_ctx_t* slipstream_client_create_stream_ctx(picoquic_cnx_t* cnx,
    slipstream_client_ctx_t* client_ctx, int sock_fd);
void slipstream_client_mark_active_pass(slipstream_client_ctx_t* client_ctx);
void slipstream_add_paths(slipstream_client_ctx_t* client_ctx);
int slipstream_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);
uint64_t test_picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidirectional);
int test_picoquic_mark_active_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int is_unidir, void* ctx);
uint64_t test_picoquic_current_time(void);
int test_picoquic_probe_new_path_ex(picoquic_cnx_t* cnx, const struct sockaddr* addr_to, const struct sockaddr* addr_from,
    int if_index, uint64_t current_time, int is_generation, int* path_id);
void test_picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t wake_time);
void test_print_sockaddr_ip_and_port(struct sockaddr_storage* addr_storage);
ssize_t test_send(int fd, const void* buf, size_t len, int flags);
int test_close(int fd);
int test_ioctl(int fd, unsigned long request, ...);
ssize_t test_recv(int fd, void* buf, size_t len, int flags);
int test_picoquic_reset_stream(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t error_code);
void test_picoquic_unlink_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id);
uint8_t* test_picoquic_provide_stream_data_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active);
int test_picoquic_wake_up_network_thread(picoquic_network_thread_ctx_t* thread_ctx);
int test_pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg);
int test_pthread_detach(pthread_t thread);
#ifndef __APPLE__
int test_pthread_setname_np(pthread_t thread, const char* name);
#else
int test_pthread_setname_np(const char* name);
#endif

extern volatile sig_atomic_t should_shutdown;

static picoquic_cnx_t mock_cnx = {0};
static picoquic_path_t* mock_paths[4] = {0};
static uint64_t next_stream_id = 0;
static int mark_active_calls = 0;
static int probe_new_path_calls = 0;
static int reinsert_calls = 0;
static bool probe_new_path_forced = false;
static int probe_new_path_result = 0;
static int probe_new_path_assigned_id = 5;

uint64_t test_picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidirectional) {
    (void)cnx;
    (void)is_unidirectional;
    fprintf(stderr, "stub next stream id -> %lu\n", (unsigned long)next_stream_id);
    return next_stream_id++;
}

int test_picoquic_mark_active_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int is_unidir, void* ctx) {
    (void)cnx;
    (void)stream_id;
    (void)is_unidir;
    (void)ctx;
    mark_active_calls++;
    return 0;
}

uint64_t test_picoquic_current_time(void) {
    return 1234;
}

int test_picoquic_probe_new_path_ex(picoquic_cnx_t* cnx, const struct sockaddr* addr_to, const struct sockaddr* addr_from,
    int if_index, uint64_t current_time, int is_generation, int* path_id) {
    (void)cnx;
    (void)addr_to;
    (void)addr_from;
    (void)if_index;
    (void)current_time;
    (void)is_generation;
    probe_new_path_calls++;
    int result = 0;
    if (probe_new_path_forced) {
        result = probe_new_path_result;
    }
    if (result == 0 && path_id != NULL) {
        *path_id = probe_new_path_assigned_id;
    }
    return result;
}

void test_picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t wake_time) {
    (void)quic;
    (void)cnx;
    (void)wake_time;
    reinsert_calls++;
}

void test_print_sockaddr_ip_and_port(struct sockaddr_storage* addr_storage) {
    (void)addr_storage;
}

int test_send_calls = 0;
int test_send_last_fd = -1;
size_t test_send_last_len = 0;
int test_send_failures_remaining = 0;
int test_send_errno = EPIPE;
ssize_t test_send_return_override = -1;
uint8_t test_send_buffer[256] = {0};

int test_close_calls = 0;
int test_closed_fds[16] = {0};

int test_ioctl_calls = 0;
int test_ioctl_should_fail = 0;
int test_ioctl_errno = 0;
int test_ioctl_last_fd = -1;
unsigned long test_ioctl_last_request = 0;
int test_ioctl_fionread_value = 0;
int test_ioctl_return_value = 0;

int test_recv_calls = 0;
int test_recv_last_fd = -1;
size_t test_recv_last_len = 0;
int test_recv_last_flags = 0;
ssize_t test_recv_return_value = 0;
int test_recv_errno = 0;
uint8_t test_recv_fill_byte = 0;

int test_picoquic_reset_stream_calls = 0;
uint64_t test_picoquic_reset_stream_ids[8] = {0};
uint64_t test_picoquic_reset_stream_errors[8] = {0};

int test_picoquic_unlink_app_stream_ctx_calls = 0;
uint64_t test_picoquic_unlink_stream_ids[8] = {0};

int test_picoquic_provide_stream_data_buffer_calls = 0;
size_t test_picoquic_provide_stream_data_buffer_last_nb_bytes = 0;
int test_picoquic_provide_stream_data_buffer_last_is_fin = 0;
int test_picoquic_provide_stream_data_buffer_last_is_active = 0;
void* test_picoquic_provide_stream_data_buffer_last_context = NULL;
uint8_t test_picoquic_provide_stream_data_buffer_storage[512] = {0};

int test_picoquic_wake_up_calls = 0;
picoquic_network_thread_ctx_t* test_picoquic_last_thread_ctx = NULL;
int test_picoquic_wake_up_return = 0;

int test_pthread_create_calls = 0;
int test_pthread_create_result = 0;
void* test_pthread_last_arg = NULL;
pthread_t test_pthread_last_thread = 0;
bool test_client_skip_arg_free = false;

int test_pthread_detach_calls = 0;

ssize_t test_send(int fd, const void* buf, size_t len, int flags) {
    ++test_send_calls;
    test_send_last_fd = fd;
    test_send_last_len = len;
    (void)flags;
    if (test_send_failures_remaining > 0) {
        --test_send_failures_remaining;
        errno = test_send_errno;
        return test_send_return_override;
    }
    size_t copy = len < sizeof(test_send_buffer) ? len : sizeof(test_send_buffer);
    if (copy > 0 && buf != NULL) {
        memcpy(test_send_buffer, buf, copy);
        if (copy < sizeof(test_send_buffer)) {
            memset(test_send_buffer + copy, 0, sizeof(test_send_buffer) - copy);
        }
    }
    return (ssize_t)len;
}

int test_close(int fd) {
    if (test_close_calls < (int)(sizeof(test_closed_fds) / sizeof(test_closed_fds[0]))) {
        test_closed_fds[test_close_calls] = fd;
    }
    ++test_close_calls;
    return 0;
}

int test_ioctl(int fd, unsigned long request, ...) {
    ++test_ioctl_calls;
    test_ioctl_last_fd = fd;
    test_ioctl_last_request = request;
    va_list args;
    va_start(args, request);
    void* argp = va_arg(args, void*);
    va_end(args);
    if (test_ioctl_should_fail) {
        errno = test_ioctl_errno;
        return -1;
    }
    if (request == (unsigned long)FIONREAD && argp != NULL) {
        *(int*)argp = test_ioctl_fionread_value;
    }
    return test_ioctl_return_value;
}

ssize_t test_recv(int fd, void* buf, size_t len, int flags) {
    ++test_recv_calls;
    test_recv_last_fd = fd;
    test_recv_last_len = len;
    test_recv_last_flags = flags;
    if (test_recv_return_value >= 0) {
        size_t copy = (size_t)test_recv_return_value;
        if (copy > len) {
            copy = len;
        }
        if (copy > 0 && buf != NULL) {
            memset(buf, test_recv_fill_byte, copy);
        }
    } else {
        errno = test_recv_errno;
    }
    return test_recv_return_value;
}

int test_picoquic_reset_stream(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t error_code) {
    (void)cnx;
    if (test_picoquic_reset_stream_calls < (int)(sizeof(test_picoquic_reset_stream_ids) / sizeof(test_picoquic_reset_stream_ids[0]))) {
        test_picoquic_reset_stream_ids[test_picoquic_reset_stream_calls] = stream_id;
        test_picoquic_reset_stream_errors[test_picoquic_reset_stream_calls] = error_code;
    }
    ++test_picoquic_reset_stream_calls;
    return 0;
}

void test_picoquic_unlink_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id) {
    (void)cnx;
    if (test_picoquic_unlink_app_stream_ctx_calls < (int)(sizeof(test_picoquic_unlink_stream_ids) / sizeof(test_picoquic_unlink_stream_ids[0]))) {
        test_picoquic_unlink_stream_ids[test_picoquic_unlink_app_stream_ctx_calls] = stream_id;
    }
    ++test_picoquic_unlink_app_stream_ctx_calls;
}

uint8_t* test_picoquic_provide_stream_data_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active) {
    test_picoquic_provide_stream_data_buffer_last_context = context;
    test_picoquic_provide_stream_data_buffer_last_nb_bytes = nb_bytes;
    test_picoquic_provide_stream_data_buffer_last_is_fin = is_fin;
    test_picoquic_provide_stream_data_buffer_last_is_active = is_still_active;
    ++test_picoquic_provide_stream_data_buffer_calls;
    return test_picoquic_provide_stream_data_buffer_storage;
}

int test_picoquic_wake_up_network_thread(picoquic_network_thread_ctx_t* thread_ctx) {
    test_picoquic_last_thread_ctx = thread_ctx;
    ++test_picoquic_wake_up_calls;
    return test_picoquic_wake_up_return;
}

int test_pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg) {
    (void)attr;
    (void)start_routine;
    ++test_pthread_create_calls;
    test_pthread_last_arg = arg;
    if (thread != NULL) {
        test_pthread_last_thread = (pthread_t)(uintptr_t)test_pthread_create_calls;
        *thread = test_pthread_last_thread;
    }
    if (test_pthread_create_result != 0) {
        return test_pthread_create_result;
    }
    if (!test_client_skip_arg_free && arg != NULL) {
        free(arg);
    }
    return 0;
}

int test_pthread_detach(pthread_t thread) {
    (void)thread;
    ++test_pthread_detach_calls;
    return 0;
}

#ifndef __APPLE__
int test_pthread_setname_np(pthread_t thread, const char* name) {
    (void)thread;
    (void)name;
    return 0;
}
#else
int test_pthread_setname_np(const char* name) {
    (void)name;
    return 0;
}
#endif

static void reset_client_test_state(void) {
    mock_cnx.path = NULL;
    mock_cnx.nb_paths = 0;
    mock_cnx.nb_path_alloc = 0;
    mock_cnx.quic = NULL;
    for (size_t i = 0; i < sizeof(mock_paths) / sizeof(mock_paths[0]); ++i) {
        mock_paths[i] = NULL;
    }
    next_stream_id = 0;
    mark_active_calls = 0;
    probe_new_path_calls = 0;
    reinsert_calls = 0;
    probe_new_path_forced = false;
    probe_new_path_result = 0;
    probe_new_path_assigned_id = 5;
    test_send_calls = 0;
    test_send_last_fd = -1;
    test_send_last_len = 0;
    test_send_failures_remaining = 0;
    test_send_errno = EPIPE;
    test_send_return_override = -1;
    memset(test_send_buffer, 0, sizeof(test_send_buffer));
    test_close_calls = 0;
    memset(test_closed_fds, 0, sizeof(test_closed_fds));
    test_ioctl_calls = 0;
    test_ioctl_should_fail = 0;
    test_ioctl_errno = 0;
    test_ioctl_last_fd = -1;
    test_ioctl_last_request = 0;
    test_ioctl_fionread_value = 0;
    test_ioctl_return_value = 0;
    test_recv_calls = 0;
    test_recv_last_fd = -1;
    test_recv_last_len = 0;
    test_recv_last_flags = 0;
    test_recv_return_value = 0;
    test_recv_errno = 0;
    test_recv_fill_byte = 0;
    test_picoquic_reset_stream_calls = 0;
    memset(test_picoquic_reset_stream_ids, 0, sizeof(test_picoquic_reset_stream_ids));
    memset(test_picoquic_reset_stream_errors, 0, sizeof(test_picoquic_reset_stream_errors));
    test_picoquic_unlink_app_stream_ctx_calls = 0;
    memset(test_picoquic_unlink_stream_ids, 0, sizeof(test_picoquic_unlink_stream_ids));
    test_picoquic_provide_stream_data_buffer_calls = 0;
    test_picoquic_provide_stream_data_buffer_last_nb_bytes = 0;
    test_picoquic_provide_stream_data_buffer_last_is_fin = 0;
    test_picoquic_provide_stream_data_buffer_last_is_active = 0;
    test_picoquic_provide_stream_data_buffer_last_context = NULL;
    memset(test_picoquic_provide_stream_data_buffer_storage, 0, sizeof(test_picoquic_provide_stream_data_buffer_storage));
    test_picoquic_wake_up_calls = 0;
    test_picoquic_last_thread_ctx = NULL;
    test_picoquic_wake_up_return = 0;
    test_pthread_create_calls = 0;
    test_pthread_create_result = 0;
    if (test_pthread_last_arg != NULL && test_client_skip_arg_free) {
        free(test_pthread_last_arg);
    }
    test_pthread_last_arg = NULL;
    test_pthread_last_thread = 0;
    test_client_skip_arg_free = false;
    test_pthread_detach_calls = 0;
    should_shutdown = 0;
}

static void test_stream_ctx_creation_and_activation(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    fprintf(stderr, "create ctx1\n");
    slipstream_client_stream_ctx_t* ctx1 = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 10);
    assert(ctx1 != NULL);
    fprintf(stderr, "created ctx1\n");
    assert(client_ctx.first_stream == ctx1);
    assert(ctx1->fd == 10);
    assert(ctx1->stream_id == (uint64_t)-1);
    assert(ctx1->next_stream == NULL);

    fprintf(stderr, "create ctx2\n");
    slipstream_client_stream_ctx_t* ctx2 = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 11);
    assert(ctx2 != NULL);
    fprintf(stderr, "created ctx2\n");
    assert(client_ctx.first_stream == ctx2);
    assert(ctx2->next_stream == ctx1);
    assert(ctx1->previous_stream == ctx2);

    ctx1->set_active = 1;
    ctx2->set_active = 1;

    next_stream_id = 100;
    fprintf(stderr, "before mark active\n");
    slipstream_client_mark_active_pass(&client_ctx);
    fprintf(stderr, "after mark active\n");
    assert(ctx1->set_active == 0);
    assert(ctx2->set_active == 0);
    assert(ctx2->stream_id == 100);
    assert(ctx1->stream_id == 101);
    assert(mark_active_calls == 2);

    client_ctx.first_stream = NULL;
    free(ctx2);
    free(ctx1);
}

static void test_add_paths_marks_additions(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    picoquic_path_t path0 = {0};
    mock_paths[0] = &path0;
    mock_cnx.path = mock_paths;
    mock_cnx.nb_paths = 1;
    mock_cnx.nb_path_alloc = (int)(sizeof mock_paths / sizeof mock_paths[0]);

    address_t addresses[3] = {0};
    client_ctx.server_addresses = addresses;
    client_ctx.server_address_count = 3;

    fprintf(stderr, "before add paths\n");
    slipstream_add_paths(&client_ctx);
    fprintf(stderr, "after add paths\n");
    assert(probe_new_path_calls == 2);
    assert(reinsert_calls == 2);
    assert(addresses[1].added);
    assert(addresses[2].added);

    slipstream_add_paths(&client_ctx);
    assert(probe_new_path_calls == 2);
}

static void test_mark_active_pass_preserves_existing_stream_id(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 20);
    assert(ctx != NULL);
    ctx->stream_id = 55;
    ctx->set_active = 1;

    next_stream_id = 999;
    slipstream_client_mark_active_pass(&client_ctx);

    assert(ctx->stream_id == 55);
    assert(next_stream_id == 999);
    assert(mark_active_calls == 1);
    assert(ctx->set_active == 0);

    client_ctx.first_stream = NULL;
    free(ctx);
}

static void test_add_paths_handles_probe_failure(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    picoquic_path_t path0 = {0};
    mock_paths[0] = &path0;
    mock_cnx.path = mock_paths;
    mock_cnx.nb_paths = 1;
    mock_cnx.nb_path_alloc = (int)(sizeof mock_paths / sizeof mock_paths[0]);

    address_t addresses[2] = {0};
    client_ctx.server_addresses = addresses;
    client_ctx.server_address_count = 2;

    probe_new_path_forced = true;
    probe_new_path_result = -1;

    slipstream_add_paths(&client_ctx);
    assert(probe_new_path_calls == 1);
    assert(reinsert_calls == 0);
    assert(addresses[1].added == false);

    probe_new_path_forced = false;
    probe_new_path_assigned_id = 7;
    probe_new_path_calls = 0;

    slipstream_add_paths(&client_ctx);
    assert(probe_new_path_calls == 1);
    assert(reinsert_calls == 1);
    assert(addresses[1].added);

    client_ctx.server_addresses = NULL;
}

static void test_client_callback_stream_data_success(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 42);
    assert(stream_ctx != NULL);

    uint8_t payload[] = {0xaa, 0xbb, 0xcc};
    int rc = slipstream_client_callback(&mock_cnx, 55, payload, sizeof(payload),
        picoquic_callback_stream_data, &client_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_send_calls == 1);
    assert(test_send_last_fd == 42);
    assert(test_send_last_len == sizeof(payload));
    assert(test_send_buffer[0] == payload[0]);
    assert(test_send_buffer[1] == payload[1]);
    assert(test_picoquic_reset_stream_calls == 0);

    rc = slipstream_client_callback(&mock_cnx, 55, NULL, 0,
        picoquic_callback_stream_fin, &client_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_close_calls == 1);
    assert(test_closed_fds[0] == 42);
    assert(test_picoquic_unlink_app_stream_ctx_calls == 1);
    assert(stream_ctx->fd == -1);

    client_ctx.first_stream = NULL;
    free(stream_ctx);
}

static void test_client_callback_stream_data_epipe_resets(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 43);
    assert(stream_ctx != NULL);

    test_send_failures_remaining = 1;
    test_send_return_override = -1;
    test_send_errno = EPIPE;

    uint8_t payload = 0u;
    int rc = slipstream_client_callback(&mock_cnx, 56, &payload, 1,
        picoquic_callback_stream_data, &client_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_send_calls == 1);
    assert(test_picoquic_reset_stream_calls == 1);
    assert(test_picoquic_reset_stream_ids[0] == 56);
    assert(test_picoquic_reset_stream_errors[0] == SLIPSTREAM_FILE_CANCEL_ERROR);

    client_ctx.first_stream = NULL;
    free(stream_ctx);
}

static void test_client_callback_prepare_to_send_reads_available(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 44);
    assert(stream_ctx != NULL);
    stream_ctx->stream_id = 200;

    test_ioctl_fionread_value = 12;
    test_recv_return_value = 12;
    test_recv_fill_byte = 0x5a;

    uint8_t quic_buffer[32] = {0};
    int rc = slipstream_client_callback(&mock_cnx, 200, quic_buffer, sizeof(quic_buffer),
        picoquic_callback_prepare_to_send, &client_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_ioctl_calls == 1);
    assert(test_ioctl_last_fd == 44);
    assert(test_ioctl_last_request == (unsigned long)FIONREAD);
    assert(test_picoquic_provide_stream_data_buffer_calls == 1);
    assert(test_picoquic_provide_stream_data_buffer_last_nb_bytes == 12);
    assert(test_picoquic_provide_stream_data_buffer_last_is_active == 1);
    assert(test_recv_calls == 1);
    assert(test_recv_last_len == 12);
    assert(test_picoquic_reset_stream_calls == 0);

    client_ctx.first_stream = NULL;
    free(stream_ctx);
}

typedef struct st_slipstream_client_poller_args {
    int fd;
    picoquic_cnx_t* cnx;
    slipstream_client_ctx_t* client_ctx;
    slipstream_client_stream_ctx_t* stream_ctx;
} slipstream_client_poller_args;

static void test_client_callback_prepare_to_send_eagain_triggers_poller(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 45);
    assert(stream_ctx != NULL);
    stream_ctx->stream_id = 300;

    test_ioctl_fionread_value = 0;
    test_recv_return_value = -1;
    test_recv_errno = EAGAIN;
    test_client_skip_arg_free = true;

    uint8_t quic_buffer[8] = {0};
    int rc = slipstream_client_callback(&mock_cnx, 300, quic_buffer, sizeof(quic_buffer),
        picoquic_callback_prepare_to_send, &client_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_picoquic_provide_stream_data_buffer_calls == 1);
    assert(test_picoquic_provide_stream_data_buffer_last_nb_bytes == 0);
    assert(test_pthread_create_calls == 1);
    assert(test_pthread_detach_calls == 1);
    assert(test_picoquic_reset_stream_calls == 0);
    assert(test_picoquic_wake_up_calls == 0);

    assert(test_pthread_last_arg != NULL);
    slipstream_client_poller_args* args = (slipstream_client_poller_args*)test_pthread_last_arg;
    assert(args->fd == 45);
    assert(args->client_ctx == &client_ctx);
    assert(args->stream_ctx == stream_ctx);

    free(test_pthread_last_arg);
    test_pthread_last_arg = NULL;
    test_client_skip_arg_free = false;

    client_ctx.first_stream = NULL;
    free(stream_ctx);
}

static void test_client_callback_stop_sending_resets_stream(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 46);
    assert(stream_ctx != NULL);

    int rc = slipstream_client_callback(&mock_cnx, 600, NULL, 0,
        picoquic_callback_stop_sending, &client_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_picoquic_reset_stream_calls == 2);
    assert(test_picoquic_reset_stream_ids[0] == 600);
    assert(test_picoquic_reset_stream_errors[0] == 0);
    assert(test_picoquic_reset_stream_ids[1] == 600);
    assert(test_picoquic_reset_stream_errors[1] == SLIPSTREAM_FILE_CANCEL_ERROR);
    assert(test_close_calls == 1);
    assert(test_closed_fds[0] == 46);
    assert(client_ctx.first_stream == NULL);
}

static void test_client_callback_stream_reset_cleans_stream(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* first = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 47);
    assert(first != NULL);
    slipstream_client_stream_ctx_t* second = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 48);
    assert(second != NULL);

    int rc = slipstream_client_callback(&mock_cnx, 601, NULL, 0,
        picoquic_callback_stream_reset, &client_ctx, second);
    assert(rc == 0);
    assert(test_picoquic_reset_stream_calls == 1);
    assert(test_picoquic_reset_stream_ids[0] == 601);
    assert(test_picoquic_reset_stream_errors[0] == SLIPSTREAM_FILE_CANCEL_ERROR);
    assert(test_close_calls == 1);
    assert(test_closed_fds[0] == 48);
    assert(client_ctx.first_stream == first);
    assert(first->next_stream == NULL);
    assert(first->previous_stream == NULL);

    client_ctx.first_stream = NULL;
    free(first);
}

static void test_client_callback_prepare_to_send_ioctl_failure_resets(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 47);
    assert(stream_ctx != NULL);
    stream_ctx->stream_id = 610;

    test_ioctl_should_fail = 1;
    test_ioctl_errno = EFAULT;

    uint8_t quic_buffer[8] = {0};
    int rc = slipstream_client_callback(&mock_cnx, 610, quic_buffer, sizeof(quic_buffer),
        picoquic_callback_prepare_to_send, &client_ctx, stream_ctx);
    assert(rc < 0);
    assert(test_ioctl_calls == 1);
    assert(test_picoquic_reset_stream_calls == 1);
    assert(test_picoquic_reset_stream_errors[0] == SLIPSTREAM_INTERNAL_ERROR);

    client_ctx.first_stream = NULL;
    free(stream_ctx);
}

static void test_client_callback_prepare_to_send_zero_bytes_resets(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 48);
    assert(stream_ctx != NULL);
    stream_ctx->stream_id = 611;

    test_ioctl_fionread_value = 0;
    test_recv_return_value = 0;

    uint8_t quic_buffer[8] = {0};
    int rc = slipstream_client_callback(&mock_cnx, 611, quic_buffer, sizeof(quic_buffer),
        picoquic_callback_prepare_to_send, &client_ctx, stream_ctx);
    assert(rc == 0);
    assert(test_recv_calls == 1);
    assert(test_picoquic_reset_stream_calls == 1);
    assert(test_picoquic_reset_stream_errors[0] == SLIPSTREAM_FILE_CANCEL_ERROR);

    client_ctx.first_stream = NULL;
    free(stream_ctx);
}

static void test_client_callback_stateless_reset_sets_shutdown(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    int rc = slipstream_client_callback(&mock_cnx, 700, NULL, 0,
        picoquic_callback_stateless_reset, &client_ctx, NULL);
    assert(rc == 0);
    assert(should_shutdown == 1);
}

static void test_client_callback_application_close_sets_shutdown(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    int rc = slipstream_client_callback(&mock_cnx, 701, NULL, 0,
        picoquic_callback_application_close, &client_ctx, NULL);
    assert(rc == 0);
    assert(should_shutdown == 1);
}

static void test_client_callback_ready_marks_ready_and_adds_paths(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    picoquic_path_t path0 = {0};
    struct sockaddr_storage local_addr = {0};
    local_addr.ss_family = AF_INET;
    path0.local_addr = local_addr;
    mock_paths[0] = &path0;
    mock_cnx.path = mock_paths;
    mock_cnx.nb_paths = 1;
    mock_cnx.nb_path_alloc = (int)(sizeof mock_paths / sizeof mock_paths[0]);
    picoquic_quic_t quic = {0};
    mock_cnx.quic = &quic;

    address_t addresses[2] = {0};
    addresses[0].server_address.ss_family = AF_INET;
    addresses[0].added = true;
    addresses[1].server_address.ss_family = AF_INET6;
    client_ctx.server_addresses = addresses;
    client_ctx.server_address_count = 2;

    int rc = slipstream_client_callback(&mock_cnx, 702, NULL, 0,
        picoquic_callback_ready, &client_ctx, NULL);
    assert(rc == 0);
    assert(client_ctx.ready);
    assert(probe_new_path_calls == 1);
    assert(reinsert_calls == 1);
    assert(addresses[1].added);

    client_ctx.server_addresses = NULL;
    mock_cnx.quic = NULL;
}

static void test_client_callback_ignores_datagram_and_path_events(void) {
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
        reset_client_test_state();

        slipstream_client_ctx_t client_ctx = {0};
        client_ctx.cnx = &mock_cnx;

        int rc = slipstream_client_callback(&mock_cnx, 800 + (uint64_t)i, NULL, 0,
            events[i], &client_ctx, NULL);
        assert(rc == 0);
        assert(test_picoquic_reset_stream_calls == 0);
        assert(test_picoquic_provide_stream_data_buffer_calls == 0);
        assert(test_pthread_create_calls == 0);
        assert(test_send_calls == 0);
        assert(should_shutdown == 0);
        assert(client_ctx.ready == false);
    }
}

static void test_client_callback_close_sets_shutdown(void) {
    reset_client_test_state();

    slipstream_client_ctx_t client_ctx = {0};
    client_ctx.cnx = &mock_cnx;

    slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(&mock_cnx, &client_ctx, 49);
    assert(stream_ctx != NULL);

    int rc = slipstream_client_callback(&mock_cnx, 612, NULL, 0,
        picoquic_callback_close, &client_ctx, stream_ctx);
    assert(rc == 0);
    assert(should_shutdown == 1);

    client_ctx.first_stream = NULL;
    free(stream_ctx);
}

int main(void) {
    fprintf(stderr, "start ctx tests\n");
    test_stream_ctx_creation_and_activation();
    fprintf(stderr, "after stream ctx test\n");
    test_add_paths_marks_additions();
    fprintf(stderr, "after add paths test\n");
    test_mark_active_pass_preserves_existing_stream_id();
    test_add_paths_handles_probe_failure();
    test_client_callback_stream_data_success();
    test_client_callback_stream_data_epipe_resets();
    test_client_callback_prepare_to_send_reads_available();
    test_client_callback_prepare_to_send_eagain_triggers_poller();
    test_client_callback_stop_sending_resets_stream();
    test_client_callback_stream_reset_cleans_stream();
    test_client_callback_prepare_to_send_ioctl_failure_resets();
    test_client_callback_prepare_to_send_zero_bytes_resets();
    test_client_callback_stateless_reset_sets_shutdown();
    test_client_callback_application_close_sets_shutdown();
    test_client_callback_ready_marks_ready_and_adds_paths();
    test_client_callback_ignores_datagram_and_path_events();
    test_client_callback_close_sets_shutdown();
    return 0;
}
