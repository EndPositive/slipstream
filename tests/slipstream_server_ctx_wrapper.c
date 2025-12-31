#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"

static int next_fd_seed = 100;
bool test_pipe_fail = false;
bool test_socket_fail = false;
int test_pipe_calls = 0;
int test_socket_calls = 0;
int test_close_calls = 0;
int test_closed_fds[8] = {0};
uint64_t test_mark_active_stream_ids[8] = {0};
void* test_mark_active_stream_ctx[8] = {0};
int test_mark_active_calls = 0;

int test_picoquic_reset_stream_calls = 0;
uint64_t test_picoquic_reset_stream_ids[8] = {0};
uint64_t test_picoquic_reset_stream_errors[8] = {0};

int test_picoquic_set_app_stream_ctx_calls = 0;
void* test_picoquic_set_app_stream_ctx_ctx[8] = {0};
int test_picoquic_set_app_stream_ctx_result = 0;

int test_picoquic_unlink_app_stream_ctx_calls = 0;
uint64_t test_picoquic_unlink_stream_ids[8] = {0};

int test_picoquic_set_callback_calls = 0;
picoquic_stream_data_cb_fn test_picoquic_last_callback_fn = NULL;
void* test_picoquic_last_callback_ctx = NULL;

int test_picoquic_close_calls = 0;
uint64_t test_picoquic_close_codes[8] = {0};

int test_picoquic_wake_up_calls = 0;
picoquic_network_thread_ctx_t* test_picoquic_last_thread_ctx = NULL;
int test_picoquic_wake_up_return = 0;

picoquic_quic_t test_quic_ctx = {0};
void* test_default_callback_ctx = NULL;

int test_pthread_create_calls = 0;
int test_pthread_create_result = 0;
void* test_pthread_last_arg = NULL;
pthread_t test_pthread_last_thread = 0;

int test_pthread_detach_calls = 0;

int test_write_calls = 0;
int test_write_last_fd = -1;
size_t test_write_last_count = 0;
uint8_t test_write_buffer[256] = {0};
int test_write_failures_remaining = 0;
int test_write_errno = EPIPE;
ssize_t test_write_return_override = -1;
bool test_skip_arg_free_on_success = false;

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

int test_picoquic_provide_stream_data_buffer_calls = 0;
size_t test_picoquic_provide_stream_data_buffer_last_nb = 0;
int test_picoquic_provide_stream_data_buffer_last_fin = 0;
int test_picoquic_provide_stream_data_buffer_last_active = 0;
void* test_picoquic_provide_stream_data_buffer_last_ctx = NULL;
uint8_t test_picoquic_provide_stream_data_buffer_storage[512] = {0};
void* test_poison_ptr = NULL;
size_t test_poison_size = 0;
bool test_poison_hit = false;

void reset_server_ctx_test_state(void) {
    next_fd_seed = 100;
    test_pipe_fail = false;
    test_socket_fail = false;
    test_pipe_calls = 0;
    test_socket_calls = 0;
    test_close_calls = 0;
    test_mark_active_calls = 0;
    test_picoquic_reset_stream_calls = 0;
    test_picoquic_set_app_stream_ctx_calls = 0;
    test_picoquic_unlink_app_stream_ctx_calls = 0;
    test_picoquic_set_callback_calls = 0;
    test_picoquic_last_callback_fn = NULL;
    test_picoquic_last_callback_ctx = NULL;
    test_picoquic_close_calls = 0;
    test_picoquic_wake_up_calls = 0;
    test_picoquic_last_thread_ctx = NULL;
   test_picoquic_wake_up_return = 0;
    test_picoquic_set_app_stream_ctx_result = 0;
    test_default_callback_ctx = NULL;
    test_pthread_create_calls = 0;
    test_pthread_create_result = 0;
    test_pthread_last_arg = NULL;
    test_pthread_last_thread = 0;
    test_pthread_detach_calls = 0;
    test_write_calls = 0;
    test_write_last_fd = -1;
    test_write_last_count = 0;
    test_write_failures_remaining = 0;
    test_write_errno = EPIPE;
    test_write_return_override = -1;
    test_skip_arg_free_on_success = false;
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
    test_picoquic_provide_stream_data_buffer_calls = 0;
    test_picoquic_provide_stream_data_buffer_last_nb = 0;
    test_picoquic_provide_stream_data_buffer_last_fin = 0;
    test_picoquic_provide_stream_data_buffer_last_active = 0;
    test_picoquic_provide_stream_data_buffer_last_ctx = NULL;
    test_poison_ptr = NULL;
    test_poison_size = 0;
    test_poison_hit = false;
    for (size_t i = 0; i < sizeof(test_write_buffer); ++i) {
        test_write_buffer[i] = 0;
    }
    memset(test_picoquic_provide_stream_data_buffer_storage, 0, sizeof(test_picoquic_provide_stream_data_buffer_storage));
    for (size_t i = 0; i < sizeof(test_closed_fds) / sizeof(test_closed_fds[0]); ++i) {
        test_closed_fds[i] = 0;
        test_mark_active_stream_ids[i] = 0;
        test_mark_active_stream_ctx[i] = NULL;
        if (i < (sizeof(test_picoquic_reset_stream_ids) / sizeof(test_picoquic_reset_stream_ids[0]))) {
            test_picoquic_reset_stream_ids[i] = 0;
            test_picoquic_reset_stream_errors[i] = 0;
            test_picoquic_set_app_stream_ctx_ctx[i] = NULL;
            test_picoquic_unlink_stream_ids[i] = 0;
            test_picoquic_close_codes[i] = 0;
        }
    }
}

int test_pipe(int pipefd[2]) {
    ++test_pipe_calls;
    if (test_pipe_fail) {
        errno = EMFILE;
        return -1;
    }
    pipefd[0] = next_fd_seed++;
    pipefd[1] = next_fd_seed++;
    return 0;
}

int test_socket(int domain, int type, int protocol) {
    ++test_socket_calls;
    if (test_socket_fail) {
        errno = EMFILE;
        return -1;
    }
    (void)domain;
    (void)type;
    (void)protocol;
    return next_fd_seed++;
}

int test_close(int fd) {
    if (test_close_calls < (int)(sizeof(test_closed_fds) / sizeof(test_closed_fds[0]))) {
        test_closed_fds[test_close_calls] = fd;
    }
    ++test_close_calls;
    return 0;
}

void test_free(void* ptr) {
    if (ptr == test_poison_ptr && test_poison_size > 0) {
        memset(ptr, 0xA5, test_poison_size);
        test_poison_hit = true;
    }
    free(ptr);
}

int test_picoquic_mark_active_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int is_unidir, void* ctx) {
    (void)cnx;
    (void)is_unidir;
    if (test_mark_active_calls < (int)(sizeof(test_mark_active_stream_ids) / sizeof(test_mark_active_stream_ids[0]))) {
        test_mark_active_stream_ids[test_mark_active_calls] = stream_id;
        test_mark_active_stream_ctx[test_mark_active_calls] = ctx;
    }
    ++test_mark_active_calls;
    return 0;
}

#define picoquic_get_quic_ctx test_picoquic_get_quic_ctx
#define picoquic_get_default_callback_context test_picoquic_get_default_callback_context
#define picoquic_set_callback test_picoquic_set_callback
#define picoquic_reset_stream test_picoquic_reset_stream
#define picoquic_set_app_stream_ctx test_picoquic_set_app_stream_ctx
#define picoquic_unlink_app_stream_ctx test_picoquic_unlink_app_stream_ctx
#define picoquic_close test_picoquic_close
#define picoquic_wake_up_network_thread test_picoquic_wake_up_network_thread
#define picoquic_provide_stream_data_buffer test_picoquic_provide_stream_data_buffer
#define pipe test_pipe
#define socket test_socket
#define write test_write
#define recv test_recv
#define ioctl test_ioctl
#define close test_close
#define free test_free
#define picoquic_mark_active_stream test_picoquic_mark_active_stream
#define should_shutdown slipstream_server_should_shutdown
#define pthread_create test_pthread_create
#define pthread_detach test_pthread_detach

#ifdef __APPLE__
#define pthread_setname_np(name) test_pthread_setname_np(name)
#else
#define pthread_setname_np(thread, name) test_pthread_setname_np(thread, name)
#endif

picoquic_quic_t* test_picoquic_get_quic_ctx(picoquic_cnx_t* cnx) {
    (void)cnx;
    return &test_quic_ctx;
}

void* test_picoquic_get_default_callback_context(picoquic_quic_t* quic) {
    (void)quic;
    return test_default_callback_ctx;
}

void test_picoquic_set_callback(picoquic_cnx_t* cnx,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx) {
    (void)cnx;
    test_picoquic_set_callback_calls++;
    test_picoquic_last_callback_fn = callback_fn;
    test_picoquic_last_callback_ctx = callback_ctx;
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

int test_picoquic_set_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id, void* stream_ctx) {
    (void)cnx;
    (void)stream_id;
    if (test_picoquic_set_app_stream_ctx_calls < (int)(sizeof(test_picoquic_set_app_stream_ctx_ctx) / sizeof(test_picoquic_set_app_stream_ctx_ctx[0]))) {
        test_picoquic_set_app_stream_ctx_ctx[test_picoquic_set_app_stream_ctx_calls] = stream_ctx;
    }
    ++test_picoquic_set_app_stream_ctx_calls;
    if (test_picoquic_set_app_stream_ctx_result != 0) {
        return test_picoquic_set_app_stream_ctx_result;
    }
    return 0;
}

void test_picoquic_unlink_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id) {
    (void)cnx;
    if (test_picoquic_unlink_app_stream_ctx_calls < (int)(sizeof(test_picoquic_unlink_stream_ids) / sizeof(test_picoquic_unlink_stream_ids[0]))) {
        test_picoquic_unlink_stream_ids[test_picoquic_unlink_app_stream_ctx_calls] = stream_id;
    }
    ++test_picoquic_unlink_app_stream_ctx_calls;
}

int test_picoquic_close(picoquic_cnx_t* cnx, uint64_t error_code) {
    (void)cnx;
    if (test_picoquic_close_calls < (int)(sizeof(test_picoquic_close_codes) / sizeof(test_picoquic_close_codes[0]))) {
        test_picoquic_close_codes[test_picoquic_close_calls] = error_code;
    }
    ++test_picoquic_close_calls;
    return 0;
}

int test_picoquic_wake_up_network_thread(picoquic_network_thread_ctx_t* thread_ctx) {
    test_picoquic_last_thread_ctx = thread_ctx;
    ++test_picoquic_wake_up_calls;
    return test_picoquic_wake_up_return;
}

ssize_t test_write(int fd, const void* buf, size_t count) {
    ++test_write_calls;
    test_write_last_fd = fd;
    test_write_last_count = count;
    if (test_write_failures_remaining > 0) {
        --test_write_failures_remaining;
        errno = test_write_errno;
        return test_write_return_override;
    }
    size_t copy_len = count < sizeof(test_write_buffer) ? count : sizeof(test_write_buffer);
    if (copy_len > 0) {
        memcpy(test_write_buffer, buf, copy_len);
        if (copy_len < sizeof(test_write_buffer)) {
            memset(test_write_buffer + copy_len, 0, sizeof(test_write_buffer) - copy_len);
        }
    }
    return (ssize_t)count;
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
        return test_recv_return_value;
    }
    errno = test_recv_errno;
    return test_recv_return_value;
}

int test_pthread_create(pthread_t* thread, const pthread_attr_t* attr,
    void* (*start_routine)(void*), void* arg) {
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
    if (!test_skip_arg_free_on_success) {
        free(arg);
    }
    return 0;
}

int test_pthread_detach(pthread_t thread) {
    ++test_pthread_detach_calls;
    (void)thread;
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

uint8_t* test_picoquic_provide_stream_data_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active) {
    test_picoquic_provide_stream_data_buffer_last_ctx = context;
    test_picoquic_provide_stream_data_buffer_last_nb = nb_bytes;
    test_picoquic_provide_stream_data_buffer_last_fin = is_fin;
    test_picoquic_provide_stream_data_buffer_last_active = is_still_active;
    ++test_picoquic_provide_stream_data_buffer_calls;
    return test_picoquic_provide_stream_data_buffer_storage;
}

#include "../src/slipstream_server.c"

void test_slipstream_server_free_stream_context(slipstream_server_ctx_t* server_ctx,
    slipstream_server_stream_ctx_t* stream_ctx) {
    slipstream_server_free_stream_context(server_ctx, stream_ctx);
}

void test_slipstream_server_free_context(slipstream_server_ctx_t* server_ctx) {
    slipstream_server_free_context(server_ctx);
}

bool test_slipstream_server_stream_ctx_acquire(slipstream_server_stream_ctx_t* stream_ctx) {
    return slipstream_server_stream_ctx_acquire(stream_ctx);
}

void test_slipstream_server_stream_ctx_release(slipstream_server_stream_ctx_t* stream_ctx) {
    slipstream_server_stream_ctx_release(stream_ctx);
}
