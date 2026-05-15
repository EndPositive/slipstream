#ifndef SLIPSTREAM_ASYNC_IO_H
#define SLIPSTREAM_ASYNC_IO_H

#include <stdint.h>
#include <stdbool.h>
#include <uv.h>

/* ============================================================================
 * ASYNC I/O CONTEXT & CONFIGURATION
 * ============================================================================ */

typedef struct {
    int max_concurrent;      /* Maximum concurrent DNS queries */
    int batch_size;          /* Queries per batch */
    int timeout_ms;          /* Query timeout in milliseconds */
    int max_retries;         /* Retries on failure */
    bool enable_pipelining;  /* Enable DNS pipelining */
} async_io_config_t;

typedef struct {
    uv_loop_t* loop;
    uv_udp_t handle;
    async_io_config_t config;
    
    /* Statistics */
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t errors;
} async_io_ctx_t;

/* ============================================================================
 * API FUNCTIONS
 * ============================================================================ */

/* Initialize async I/O context */
async_io_ctx_t* async_io_create(const async_io_config_t* config);

/* Destroy async I/O context */
void async_io_destroy(async_io_ctx_t* ctx);

/* Send single DNS query (async) */
int async_io_send(async_io_ctx_t* ctx, const uint8_t* packet, size_t packet_len,
                  const char* server_ip, uint16_t server_port);

/* Send batch of DNS queries (pipelined) */
int async_io_send_batch(async_io_ctx_t* ctx, const uint8_t** packets, 
                        const size_t* sizes, size_t num_packets,
                        const char* server_ip, uint16_t server_port);

/* Poll for responses with timeout */
int async_io_poll(async_io_ctx_t* ctx, int timeout_ms);

/* Get next response (non-blocking) */
int async_io_recv(async_io_ctx_t* ctx, uint8_t* buffer, size_t buffer_size,
                  struct sockaddr_storage* peer_addr);

/* Get statistics */
void async_io_get_stats(async_io_ctx_t* ctx, uint64_t* sent, uint64_t* recv, uint64_t* err);

#endif /* SLIPSTREAM_ASYNC_IO_H */
