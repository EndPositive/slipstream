#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "slipstream_utils.h"

uint64_t test_picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidirectional);
int test_picoquic_mark_active_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int is_unidir, void* ctx);
uint64_t test_picoquic_current_time(void);
int test_picoquic_probe_new_path_ex(picoquic_cnx_t* cnx, const struct sockaddr* addr_to, const struct sockaddr* addr_from,
    int if_index, uint64_t current_time, int is_generation, int* path_id);
void test_picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t wake_time);
void test_print_sockaddr_ip_and_port(struct sockaddr_storage* addr_storage);
ssize_t test_send(int fd, const void* buf, size_t len, int flags);
ssize_t test_recv(int fd, void* buf, size_t len, int flags);
int test_close(int fd);
int test_ioctl(int fd, unsigned long request, ...);
int test_picoquic_reset_stream(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t error_code);
void test_picoquic_unlink_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id);
uint8_t* test_picoquic_provide_stream_data_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active);
int test_picoquic_wake_up_network_thread(picoquic_network_thread_ctx_t* thread_ctx);
int test_pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg);
int test_pthread_detach(pthread_t thread);
#ifdef __APPLE__
int test_pthread_setname_np(const char* name);
#else
int test_pthread_setname_np(pthread_t thread, const char* name);
#endif

#define picoquic_get_next_local_stream_id test_picoquic_get_next_local_stream_id
#define picoquic_mark_active_stream test_picoquic_mark_active_stream
#define picoquic_probe_new_path_ex test_picoquic_probe_new_path_ex
#define picoquic_reinsert_by_wake_time test_picoquic_reinsert_by_wake_time
#define picoquic_current_time test_picoquic_current_time
#define print_sockaddr_ip_and_port test_print_sockaddr_ip_and_port
#define picoquic_reset_stream test_picoquic_reset_stream
#define picoquic_unlink_app_stream_ctx test_picoquic_unlink_app_stream_ctx
#define picoquic_provide_stream_data_buffer test_picoquic_provide_stream_data_buffer
#define picoquic_wake_up_network_thread test_picoquic_wake_up_network_thread
#define send test_send
#define recv test_recv
#define close test_close
#define ioctl test_ioctl
#define pthread_create test_pthread_create
#define pthread_detach test_pthread_detach

#ifdef __APPLE__
#define pthread_setname_np(name) test_pthread_setname_np(name)
#else
#define pthread_setname_np(thread, name) test_pthread_setname_np(thread, name)
#endif

#include "../src/slipstream_client.c"
