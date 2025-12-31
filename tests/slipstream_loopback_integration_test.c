#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "slipstream.h"
#include "picoquic/picoquic_utils.h"

extern volatile sig_atomic_t slipstream_client_should_shutdown;
extern volatile sig_atomic_t slipstream_server_should_shutdown;

static const char* const k_cert_path = "../certs/cert.pem";
static const char* const k_key_path = "../certs/key.pem";
static const char* const k_test_domain = "loopback.test";
static bool debug_enabled = false;

static void debug_log(const char* fmt, ...) {
    if (!debug_enabled) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

static uint16_t reserve_loopback_port(int sock_type) {
    int fd = socket(AF_INET, sock_type, 0);
    assert(fd >= 0);

    int reuse = 1;
    assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);

    socklen_t addr_len = sizeof(addr);
    assert(getsockname(fd, (struct sockaddr*)&addr, &addr_len) == 0);

    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    uint16_t port;
    bool ready;
    bool done;
    const char* const* expected_requests;
    const char* const* responses;
    size_t exchange_count;
    size_t completed;
    int result;
} target_server_state_t;

static void target_state_init(target_server_state_t* state,
    const char* const* requests,
    const char* const* responses,
    size_t exchange_count) {
    pthread_mutex_init(&state->mutex, NULL);
    pthread_cond_init(&state->cond, NULL);
    state->port = 0;
    state->ready = false;
    state->done = false;
    state->expected_requests = requests;
    state->responses = responses;
    state->exchange_count = exchange_count;
    state->completed = 0;
    state->result = 0;
}

static bool is_wouldblock(int err) {
    if (err == EAGAIN) {
        return true;
    }
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    if (err == EWOULDBLOCK) {
        return true;
    }
#endif
    return false;
}

static ssize_t blocking_send(int fd, const char* buf, size_t len, size_t* sent_total) {
    ssize_t sent = send(fd, buf + *sent_total, len - *sent_total, 0);
    if (sent > 0) {
        *sent_total += (size_t)sent;
    }
    return sent;
}

static ssize_t blocking_recv(int fd, char* buf, size_t len, size_t* recv_total) {
    ssize_t recvd = recv(fd, buf + *recv_total, len - *recv_total, 0);
    if (recvd > 0) {
        *recv_total += (size_t)recvd;
    }
    return recvd;
}

static void close_if_valid(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

static void* target_server_finish(target_server_state_t* state, int listen_fd, int client_fd, size_t completed) {
    close_if_valid(client_fd);
    close_if_valid(listen_fd);

    pthread_mutex_lock(&state->mutex);
    state->completed = completed;
    state->ready = true;
    state->done = true;
    pthread_cond_broadcast(&state->cond);
    pthread_mutex_unlock(&state->mutex);

    if (state->result != 0) {
        debug_log("[target] exiting with result %d after %zu exchanges", state->result, completed);
    } else {
        debug_log("[target] completed %zu exchanges successfully", completed);
    }
    return NULL;
}

static void* target_server_fail(target_server_state_t* state, int listen_fd, int client_fd, size_t completed, int result) {
    state->result = result;
    return target_server_finish(state, listen_fd, client_fd, completed);
}

static void* target_server_main(void* arg) {
    target_server_state_t* state = (target_server_state_t*)arg;
    debug_log("[target] thread started");

    int listen_fd = -1;
    int client_fd = -1;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return target_server_fail(state, listen_fd, client_fd, 0, -errno);
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        return target_server_fail(state, listen_fd, client_fd, 0, -errno);
    }

    if (listen(listen_fd, 1) != 0) {
        return target_server_fail(state, listen_fd, client_fd, 0, -errno);
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(listen_fd, (struct sockaddr*)&addr, &addr_len) != 0) {
        return target_server_fail(state, listen_fd, client_fd, 0, -errno);
    }

    pthread_mutex_lock(&state->mutex);
    state->port = ntohs(addr.sin_port);
    state->ready = true;
    pthread_cond_broadcast(&state->cond);
    pthread_mutex_unlock(&state->mutex);
    debug_log("[target] listening on %u", state->port);

    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        return target_server_fail(state, listen_fd, client_fd, 0, -errno);
    }

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t completed = 0;
    char exchange_buffer[256];

    const int max_timeouts = 6;

    for (size_t i = 0; i < state->exchange_count; ++i) {
        const char* expected = state->expected_requests[i];
        size_t expected_len = strlen(expected);
        if (expected_len > sizeof(exchange_buffer)) {
            return target_server_fail(state, listen_fd, client_fd, completed, -EOVERFLOW);
        }

        memset(exchange_buffer, 0, sizeof(exchange_buffer));
        size_t received_total = 0;
        int recv_timeouts = 0;

        while (received_total < expected_len) {
            ssize_t recvd = blocking_recv(client_fd, exchange_buffer, expected_len, &received_total);
            if (recvd == 0) {
                return target_server_fail(state, listen_fd, client_fd, completed, -ECONNRESET);
            }
            if (recvd < 0) {
                int err = errno;
                if (err == EINTR) {
                    continue;
                }
                if (is_wouldblock(err)) {
                    if (++recv_timeouts > max_timeouts) {
                        return target_server_fail(state, listen_fd, client_fd, completed, -ETIMEDOUT);
                    }
                    continue;
                }
                return target_server_fail(state, listen_fd, client_fd, completed, -err);
            }
            recv_timeouts = 0;
            debug_log("[target] received %zd bytes (%zu/%zu) for request %zu", recvd, received_total, expected_len, i);
        }

        if (memcmp(exchange_buffer, expected, expected_len) != 0) {
            return target_server_fail(state, listen_fd, client_fd, completed, -EINVAL);
        }
        debug_log("[target] verified request %zu '%s'", i, expected);

        const char* response = state->responses[i];
        size_t response_len = strlen(response);
        size_t sent_total = 0;
        int send_timeouts = 0;

        while (sent_total < response_len) {
            ssize_t sent = blocking_send(client_fd, response, response_len, &sent_total);
            if (sent < 0) {
                int err = errno;
                if (err == EINTR) {
                    continue;
                }
                if (is_wouldblock(err)) {
                    if (++send_timeouts > max_timeouts) {
                        return target_server_fail(state, listen_fd, client_fd, completed, -ETIMEDOUT);
                    }
                    continue;
                }
                return target_server_fail(state, listen_fd, client_fd, completed, -err);
            }
            debug_log("[target] sent %zd bytes (%zu/%zu) for response %zu", sent, sent_total, response_len, i);
        }

        completed = i + 1;
    }

    return target_server_finish(state, listen_fd, client_fd, completed);
}

typedef struct {
    uint16_t server_port;
    struct sockaddr_storage target_addr;
    int result;
} server_thread_args_t;

typedef struct {
    uint16_t client_listen_port;
    uint16_t server_port;
    int result;
} client_thread_args_t;

static void* slipstream_server_main(void* arg) {
    server_thread_args_t* args = (server_thread_args_t*)arg;
    slipstream_server_should_shutdown = 0;
    int ret = picoquic_slipstream_server((int)args->server_port, false, k_cert_path, k_key_path,
        &args->target_addr, k_test_domain);
    args->result = ret;
    debug_log("[server] thread exiting with result %d", ret);
    return NULL;
}

static void* slipstream_client_main(void* arg) {
    client_thread_args_t* args = (client_thread_args_t*)arg;
    slipstream_client_should_shutdown = 0;

    address_t server_address = {0};
    struct sockaddr_in* sin = (struct sockaddr_in*)&server_address.server_address;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin->sin_port = htons(args->server_port);

    int ret = picoquic_slipstream_client((int)args->client_listen_port,
        &server_address, 1, k_test_domain, NULL, false, 0);
    args->result = ret;
    debug_log("[client] thread exiting with result %d", ret);
    return NULL;
}

static int connect_with_retry(uint16_t port, int attempts, int delay_ms) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    for (int attempt = 0; attempt < attempts; ++attempt) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            return fd;
        }
        close(fd);
        struct timespec ts = {.tv_sec = 0, .tv_nsec = (long)delay_ms * 1000000L};
        nanosleep(&ts, NULL);
    }
    return -1;
}

int main(void) {
    const char* debug_env = getenv("SLIPSTREAM_DEBUG_LOG");
    if (debug_env != NULL && debug_env[0] != '\0') {
        debug_printf_push_stream(stderr);
        debug_enabled = true;
        debug_log("[test] debug logging enabled");
    }

    const char* client_requests[] = {
        "slipstream-loopback-request",
        "slipstream-second-request"
    };
    const char* expected_responses[] = {
        "slipstream-loopback-response",
        "slipstream-second-response"
    };
    const size_t exchange_count = sizeof(client_requests) / sizeof(client_requests[0]);

    int probe_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (probe_fd < 0) {
        if (errno == EPERM || errno == EACCES
#if defined(ENOTCAPABLE)
            || errno == ENOTCAPABLE
#endif
        ) {
            fprintf(stderr,
                "slipstream-loopback-integration: skipping test (socket permission error: %s)\n",
                strerror(errno));
            return 77;
        }
        perror("socket");
        return EXIT_FAILURE;
    }
    close(probe_fd);

    target_server_state_t target_state;
    target_state_init(&target_state, client_requests, expected_responses, exchange_count);

    pthread_t target_thread;
    assert(pthread_create(&target_thread, NULL, target_server_main, &target_state) == 0);

    pthread_mutex_lock(&target_state.mutex);
    while (!target_state.ready) {
        pthread_cond_wait(&target_state.cond, &target_state.mutex);
    }
    uint16_t target_port = target_state.port;
    pthread_mutex_unlock(&target_state.mutex);

    uint16_t server_port = reserve_loopback_port(SOCK_DGRAM);
    uint16_t client_port = reserve_loopback_port(SOCK_STREAM);

    server_thread_args_t server_args = {0};
    server_args.server_port = server_port;
    memset(&server_args.target_addr, 0, sizeof(server_args.target_addr));
    struct sockaddr_in* upstream = (struct sockaddr_in*)&server_args.target_addr;
    upstream->sin_family = AF_INET;
    upstream->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    upstream->sin_port = htons(target_port);

    pthread_t server_thread;
    assert(pthread_create(&server_thread, NULL, slipstream_server_main, &server_args) == 0);

    struct timespec short_delay = {.tv_sec = 0, .tv_nsec = 200000000L};
    nanosleep(&short_delay, NULL);

    client_thread_args_t client_args = {0};
    client_args.client_listen_port = client_port;
    client_args.server_port = server_port;

    pthread_t client_thread;
    assert(pthread_create(&client_thread, NULL, slipstream_client_main, &client_args) == 0);

    nanosleep(&short_delay, NULL);

    int local_fd = connect_with_retry(client_port, 50, 50);
    if (local_fd < 0) {
        debug_log("[test] failed to connect to slipstream client: %s", strerror(errno));
    }
    assert(local_fd >= 0);

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(local_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const int max_timeouts = 6;

    for (size_t i = 0; i < exchange_count; ++i) {
        const char* request = client_requests[i];
        size_t request_len = strlen(request);
        size_t sent_total = 0;
        int send_timeouts = 0;
        while (sent_total < request_len) {
            ssize_t sent = blocking_send(local_fd, request, request_len, &sent_total);
            if (sent < 0) {
                int err = errno;
                if (err == EINTR) {
                    continue;
                }
                if (is_wouldblock(err)) {
                    if (++send_timeouts > max_timeouts) {
                        debug_log("[test] send retry exhaustion for request %zu after %zu bytes", i, sent_total);
                        assert(false && "send retries exhausted");
                    }
                    continue;
                }
                debug_log("[test] send failed for request %zu: errno=%d (%s)", i, err, strerror(err));
                assert(false && "send failed");
            }
        }

        const char* expected = expected_responses[i];
        size_t expected_len = strlen(expected);
        size_t received_total = 0;
        char reply_buffer[256] = {0};
        int recv_timeouts = 0;

        while (received_total < expected_len) {
            ssize_t recvd = blocking_recv(local_fd, reply_buffer, expected_len, &received_total);
            if (recvd == 0) {
                debug_log("[test] recv returned EOF for response %zu after %zu bytes", i, received_total);
                assert(false && "unexpected EOF");
            }
            if (recvd < 0) {
                int err = errno;
                if (err == EINTR) {
                    continue;
                }
                if (is_wouldblock(err)) {
                    debug_log("[test] recv timeout for response %zu (received %zu/%zu), retry %d/%d",
                        i, received_total, expected_len, recv_timeouts + 1, max_timeouts);
                    if (++recv_timeouts > max_timeouts) {
                        debug_log("[test] giving up waiting for response %zu after %d timeouts", i, recv_timeouts);
                        assert(false && "timed out waiting for response data");
                    }
                    continue;
                }
                debug_log("[test] recv failed for response %zu: errno=%d (%s)", i, err, strerror(err));
                assert(false && "recv failed");
            }
            recv_timeouts = 0;
        }
        assert(memcmp(reply_buffer, expected, expected_len) == 0);
    }

    close(local_fd);

    pthread_mutex_lock(&target_state.mutex);
    while (!target_state.done) {
        pthread_cond_wait(&target_state.cond, &target_state.mutex);
    }
    pthread_mutex_unlock(&target_state.mutex);

    debug_log("[test] target_state.result=%d completed=%zu/%zu", target_state.result, target_state.completed, exchange_count);
    assert(target_state.result == 0);
    assert(target_state.completed == exchange_count);

    slipstream_client_should_shutdown = 1;
    slipstream_server_should_shutdown = 1;
    pthread_kill(client_thread, SIGTERM);
    pthread_kill(server_thread, SIGTERM);

    pthread_join(client_thread, NULL);
    pthread_join(server_thread, NULL);
    pthread_join(target_thread, NULL);

    assert(client_args.result == 0 || client_args.result == -1);
    assert(server_args.result == 0 || server_args.result == -1);

    slipstream_client_should_shutdown = 0;
    slipstream_server_should_shutdown = 0;

    return 0;
}
