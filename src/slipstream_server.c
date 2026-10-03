#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_packet_loop.h>
#include <picosocks.h>
#ifdef BUILD_LOGLIB
#include <autoqlog.h>
#endif
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/nameser.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <assert.h>
#include <picoquic_internal.h>
#include <slipstream_sockloop.h>

#include "lua-resty-base-encoding-base32.h"
#include "picoquic_config.h"
#include "picoquic_logger.h"
#include "slipstream.h"
#include "slipstream_inline_dots.h"
#include "../include/slipstream_server_cc.h"
#include "slipstream_slot.h"
#include "slipstream_utils.h"
#include "SPCDNS/src/dns.h"
#include "SPCDNS/src/mappings.h"

volatile sig_atomic_t should_shutdown = 0;

void server_sighandler(int signum) {
    (void)signum;
    should_shutdown = 1;
}

char* server_domain_name = NULL;
size_t server_domain_name_len = 0;

ssize_t server_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, size_t* segment_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr) {
    *dest_buf = NULL;

    // we don't support segmentation in the server
    assert(segment_len == NULL || *segment_len == 0 || *segment_len == src_buf_len);

    slot_t* slot = (slot_t*) slot_p;

#ifdef NOENCODE
    *dest_buf = malloc(src_buf_len);
    memcpy((void*)*dest_buf, src_buf, src_buf_len);

    memcpy(peer_addr, &slot->peer_addr, sizeof(struct sockaddr_storage));
    memcpy(local_addr, &slot->local_addr, sizeof(struct sockaddr_storage));

    return src_buf_len;
#endif

    dns_query_t *query = (dns_query_t *) slot->dns_decoded;
    dns_txt_t answer_txt; // TODO: fix
    dns_answer_t edns = {0};
    edns.opt.name = ".";
    edns.opt.type = RR_OPT;
    edns.opt.class = CLASS_UNKNOWN;
    edns.opt.ttl = 0;
    edns.opt.udp_payload = 1232;

    dns_query_t response = {0};
    response.id = query->id;
    response.query = false;
    response.opcode = OP_QUERY;
    response.aa = true;
    response.rd = query->rd;
    response.cd = query->cd;
    response.rcode = slot->error;
    response.qdcount = 1;
    response.questions = query->questions;

    if (src_buf_len > 0) {
        const dns_question_t *question = &query->questions[0]; // assuming server_decode ensures there is exactly one question
        answer_txt.name = question->name;
        answer_txt.type = question->type;
        answer_txt.class = question->class;
        answer_txt.ttl = 60;
        answer_txt.text = (char *)src_buf;
        answer_txt.len = src_buf_len;

        response.ancount = 1;
        response.answers = (dns_answer_t *)&answer_txt;
    }
    /* An empty successful poll is NOERROR/NODATA, not a nonexistent name.
     * Preserve actual decode errors already stored in slot->error. */

    response.arcount = 1;
    response.additional = &edns;

    dns_packet_t* packet = malloc(MAX_UDP_PACKET_SIZE);
    size_t packet_len = MAX_UDP_PACKET_SIZE;
    dns_rcode_t rc = dns_encode(packet, &packet_len, &response);
    if (rc != RCODE_OKAY) {
        free(packet);
        DBG_PRINTF("dns_encode() = (%d) %s", rc, dns_rcode_text(rc));
        return EXIT_FAILURE;
    }
    *dest_buf = (unsigned char*)packet;

    memcpy(peer_addr, &slot->peer_addr, sizeof(struct sockaddr_storage));
    memcpy(local_addr, &slot->local_addr, sizeof(struct sockaddr_storage));

    return packet_len;
}

ssize_t server_decode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage *peer_addr, struct sockaddr_storage *local_addr) {
    *dest_buf = NULL;

    slot_t* slot = slot_p;

    // DNS packets arrive from random source ports, so:
    // * save the original address in the dns query slot
    // * set the source address to a dummy address (to prevent QUIC from using it)
    memcpy(&slot->peer_addr, peer_addr, sizeof(struct sockaddr_storage));
    sockaddr_dummy(peer_addr);
    // Save local address for right response local addr
    memcpy(&slot->local_addr, local_addr, sizeof(struct sockaddr_storage));

#ifdef NODECODE
    *dest_buf = malloc(src_buf_len);
    memcpy((void*)*dest_buf, src_buf, src_buf_len);

    return src_buf_len;
#endif

    size_t packet_len = DNS_DECODEBUF_4K * sizeof(dns_decoded_t);
    dns_decoded_t* packet = slot->dns_decoded;
    const dns_rcode_t rc = dns_decode(packet, &packet_len, (const dns_packet_t*) src_buf, src_buf_len);
    if (rc != RCODE_OKAY) {
        DBG_PRINTF("dns_decode() = (%d) %s", rc, dns_rcode_text(rc));
        // TODO: how to get rid of this packet
        return -1; // TODO: server failure
    }

    const dns_query_t *query = (dns_query_t*) packet;
    if (!query->query) {
        DBG_PRINTF("dns record is not a query", NULL);
        slot->error = RCODE_FORMAT_ERROR;
        return 0;
    }

    if (query->qdcount != 1) {
        DBG_PRINTF("dns record should contain exactly one query", NULL);
        slot->error = RCODE_FORMAT_ERROR;
        return 0;
    }

    const dns_question_t *question = &query->questions[0];
    if (question->type != RR_TXT) {
        // resolvers send anything for pinging, so we only respond to TXT queries
        // DBG_PRINTF("query type is not TXT", NULL);
        slot->error = RCODE_NAME_ERROR;
        return 0;
    }

    const ssize_t data_len = strlen(question->name) - server_domain_name_len - 1 - 1;
    if (data_len <= 0) {
        DBG_PRINTF("subdomain is empty", NULL);
        slot->error = RCODE_NAME_ERROR;
        return 0;
    }

    // copy the subdomain from name to a new buffer
    char data_buf[data_len + 1];
    memcpy(data_buf, question->name, data_len);
    data_buf[data_len] = '\0';
    const size_t encoded_len = slipstream_inline_undotify(data_buf, data_len);

    char* decoded_buf = malloc(encoded_len);
    const size_t decoded_len = b32_decode(decoded_buf, data_buf, encoded_len, false);
    if (decoded_len == (size_t) -1) {
        free(decoded_buf);
        DBG_PRINTF("error decoding base32: %lu", decoded_len);
        slot->error = RCODE_SERVER_FAILURE;
        return 0;
    }

    *dest_buf = decoded_buf;

    return decoded_len;
}

/* All stream state and descriptors belong exclusively to the network thread.
 * No detached workers retain stream, connection, or network-loop pointers. */
#define SLIPSTREAM_PENDING_LIMIT (1024 * 1024)
#define SLIPSTREAM_WRITE_BUDGET (64 * 1024)
#define SLIPSTREAM_CONNECT_TIMEOUT_US (30ULL * 1000000)

typedef struct st_slipstream_pending_t {
    struct st_slipstream_pending_t* next;
    size_t length;
    size_t offset;
    uint8_t data[];
} slipstream_pending_t;

typedef struct st_slipstream_server_stream_ctx_t {
    struct st_slipstream_server_stream_ctx_t* next_stream;
    struct st_slipstream_server_stream_ctx_t* previous_stream;
    struct st_slipstream_server_ctx_t* owner;
    int fd;
    uint64_t stream_id;
    uint64_t connect_deadline;
    bool connecting;
    bool read_wait;
    bool peer_fin;
    bool write_shutdown;
    bool send_fin;
    size_t pending_bytes;
    slipstream_pending_t* pending_first;
    slipstream_pending_t* pending_last;
} slipstream_server_stream_ctx_t;

typedef struct st_slipstream_server_ctx_t {
    picoquic_cnx_t* cnx;
    slipstream_server_stream_ctx_t* first_stream;
    struct sockaddr_storage upstream_addr;
    struct st_slipstream_server_ctx_t* prev_ctx;
    struct st_slipstream_server_ctx_t* next_ctx;
    /* Only the default context owns the reusable poll arrays. */
    struct pollfd* poll_fds;
    slipstream_server_stream_ctx_t** poll_streams;
    size_t poll_capacity;
} slipstream_server_ctx_t;

static void slipstream_server_free_stream_context(slipstream_server_ctx_t* server_ctx,
                                                  slipstream_server_stream_ctx_t* stream_ctx) {
    /* Clear PicoQUIC's borrowed pointer before destroying the owner. */
    picoquic_unlink_app_stream_ctx(server_ctx->cnx, stream_ctx->stream_id);
    if (stream_ctx->previous_stream != NULL) {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    } else {
        server_ctx->first_stream = stream_ctx->next_stream;
    }
    if (stream_ctx->next_stream != NULL) {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }
    close(stream_ctx->fd);
    while (stream_ctx->pending_first != NULL) {
        slipstream_pending_t* pending = stream_ctx->pending_first;
        stream_ctx->pending_first = pending->next;
        free(pending);
    }
    free(stream_ctx);
}

static void slipstream_server_abort_stream(slipstream_server_ctx_t* server_ctx,
                                          slipstream_server_stream_ctx_t* stream_ctx,
                                          uint64_t error_code) {
    uint64_t stream_id = stream_ctx->stream_id;
    slipstream_server_free_stream_context(server_ctx, stream_ctx);
    (void)picoquic_stop_sending(server_ctx->cnx, stream_id, error_code);
    (void)picoquic_reset_stream(server_ctx->cnx, stream_id, error_code);
}

static void slipstream_server_free_context(slipstream_server_ctx_t* server_ctx) {
    while (server_ctx->first_stream != NULL) {
        slipstream_server_free_stream_context(server_ctx, server_ctx->first_stream);
    }
    if (server_ctx->prev_ctx != NULL) {
        server_ctx->prev_ctx->next_ctx = server_ctx->next_ctx;
    }
    if (server_ctx->next_ctx != NULL) {
        server_ctx->next_ctx->prev_ctx = server_ctx->prev_ctx;
    }
    free(server_ctx);
}

static slipstream_server_stream_ctx_t* slipstream_server_create_stream_ctx(
    slipstream_server_ctx_t* server_ctx, uint64_t stream_id) {
    socklen_t addr_len;
    int af = server_ctx->upstream_addr.ss_family;
    if (af == AF_INET) {
        addr_len = sizeof(struct sockaddr_in);
    } else if (af == AF_INET6) {
        addr_len = sizeof(struct sockaddr_in6);
    } else {
        fprintf(stderr, "Invalid upstream address family\n");
        return NULL;
    }
    slipstream_server_stream_ctx_t* stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (stream_ctx == NULL) {
        return NULL;
    }
    stream_ctx->fd = socket(af, SOCK_STREAM, 0);
    if (stream_ctx->fd < 0) {
        perror("socket() failed");
        free(stream_ctx);
        return NULL;
    }
    int flags = fcntl(stream_ctx->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(stream_ctx->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("Unable to make upstream socket nonblocking");
        goto fail;
    }
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(stream_ctx->fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
        perror("Unable to disable SIGPIPE on upstream socket");
        goto fail;
    }
#endif
    if (connect(stream_ctx->fd, (struct sockaddr*)&server_ctx->upstream_addr, addr_len) < 0) {
        if (errno != EINPROGRESS && errno != EINTR) {
            perror("connect() failed");
            goto fail;
        }
        stream_ctx->connecting = true;
        stream_ctx->connect_deadline = picoquic_current_time() + SLIPSTREAM_CONNECT_TIMEOUT_US;
    }
    stream_ctx->owner = server_ctx;
    stream_ctx->stream_id = stream_id;
    stream_ctx->read_wait = true;
    stream_ctx->next_stream = server_ctx->first_stream;
    if (stream_ctx->next_stream != NULL) {
        stream_ctx->next_stream->previous_stream = stream_ctx;
    }
    server_ctx->first_stream = stream_ctx;
    return stream_ctx;
fail:
    close(stream_ctx->fd);
    free(stream_ctx);
    return NULL;
}

/* Return an error without freeing: the caller owns cleanup and iteration. */
static int slipstream_server_flush(slipstream_server_stream_ctx_t* stream_ctx) {
    if (stream_ctx->connecting) {
        return 0;
    }
    size_t budget = SLIPSTREAM_WRITE_BUDGET;
    while (stream_ctx->pending_first != NULL && budget > 0) {
        slipstream_pending_t* pending = stream_ctx->pending_first;
        size_t length = MIN(pending->length - pending->offset, budget);
        int flags = 0;
#ifdef MSG_NOSIGNAL
        flags = MSG_NOSIGNAL;
#endif
        ssize_t n = send(stream_ctx->fd, pending->data + pending->offset, length, flags);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            perror("send() failed");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "send() made no progress\n");
            return -1;
        }
        pending->offset += (size_t)n;
        stream_ctx->pending_bytes -= (size_t)n;
        budget -= (size_t)n;
        if (pending->offset == pending->length) {
            stream_ctx->pending_first = pending->next;
            if (stream_ctx->pending_first == NULL) {
                stream_ctx->pending_last = NULL;
            }
            free(pending);
        }
    }
    if (stream_ctx->peer_fin && stream_ctx->pending_first == NULL && !stream_ctx->write_shutdown) {
        /* FIN is a half-close, propagated only after queued request data. */
        if (shutdown(stream_ctx->fd, SHUT_WR) != 0) {
            perror("shutdown(SHUT_WR) failed");
            return -1;
        }
        stream_ctx->write_shutdown = true;
    }
    return 0;
}

static bool slipstream_server_stream_done(const slipstream_server_stream_ctx_t* stream_ctx) {
    return stream_ctx->send_fin && stream_ctx->write_shutdown;
}

static int slipstream_server_queue(slipstream_server_stream_ctx_t* stream_ctx,
                                   const uint8_t* bytes, size_t length) {
    if (length == 0) {
        return 0;
    }
    if (length > SLIPSTREAM_PENDING_LIMIT - stream_ctx->pending_bytes) {
        fprintf(stderr, "Upstream write queue exceeded %d bytes on stream %llu\n",
            SLIPSTREAM_PENDING_LIMIT, (unsigned long long)stream_ctx->stream_id);
        return -1;
    }
    slipstream_pending_t* pending = malloc(sizeof(*pending) + length);
    if (pending == NULL) {
        return -1;
    }
    pending->next = NULL;
    pending->length = length;
    pending->offset = 0;
    memcpy(pending->data, bytes, length);
    if (stream_ctx->pending_last != NULL) {
        stream_ctx->pending_last->next = pending;
    } else {
        stream_ctx->pending_first = pending;
    }
    stream_ctx->pending_last = pending;
    stream_ctx->pending_bytes += length;
    return 0;
}

/* Wait for DNS and upstream readiness together. An activated QUIC stream is
 * no longer polled for reads until prepare_to_send consumes it or sees EAGAIN;
 * otherwise a readable TCP socket would spin while awaiting another DNS poll. */
static int slipstream_server_poll(slipstream_server_ctx_t* default_ctx,
                                  picoquic_socket_ctx_t* dns_socket) {
    size_t count = 1;
    for (slipstream_server_ctx_t* ctx = default_ctx->next_ctx; ctx != NULL; ctx = ctx->next_ctx) {
        for (slipstream_server_stream_ctx_t* stream = ctx->first_stream; stream != NULL; stream = stream->next_stream) {
            count++;
        }
    }
    if (count > default_ctx->poll_capacity) {
        /* Grow both arrays together; failure preserves the old allocation. */
        struct pollfd* fds = calloc(count, sizeof(*fds));
        slipstream_server_stream_ctx_t** streams = calloc(count, sizeof(*streams));
        if (fds == NULL || streams == NULL) {
            free(fds);
            free(streams);
            return -1;
        }
        free(default_ctx->poll_fds);
        free(default_ctx->poll_streams);
        default_ctx->poll_fds = fds;
        default_ctx->poll_streams = streams;
        default_ctx->poll_capacity = count;
    }
    struct pollfd* fds = default_ctx->poll_fds;
    slipstream_server_stream_ctx_t** streams = default_ctx->poll_streams;
    fds[0] = (struct pollfd){.fd = dns_socket->fd, .events = POLLIN};
    size_t i = 1;
    int timeout = 1000; /* also bound signal/shutdown and connect-deadline latency */
    uint64_t now = picoquic_current_time();
    for (slipstream_server_ctx_t* ctx = default_ctx->next_ctx; ctx != NULL; ctx = ctx->next_ctx) {
        for (slipstream_server_stream_ctx_t* stream = ctx->first_stream; stream != NULL; stream = stream->next_stream) {
            short events = 0;
            if (stream->connecting || stream->pending_first != NULL) {
                events |= POLLOUT;
            }
            if (!stream->connecting && stream->read_wait && !stream->send_fin) {
                events |= POLLIN;
            }
            /* Negative fd suppresses HUP/ERR on a socket with no work. */
            fds[i] = (struct pollfd){.fd = events ? stream->fd : -1, .events = events};
            streams[i++] = stream;
            if (stream->connecting) {
                uint64_t remaining = stream->connect_deadline > now ? stream->connect_deadline - now : 0;
                int ms = (int)MIN((remaining + 999) / 1000, 1000);
                timeout = MIN(timeout, ms);
            }
        }
    }
    int ret = poll(fds, count, timeout);
    if (ret < 0) {
        if (errno == EINTR) {
            return 0;
        }
        perror("poll() failed");
        return -1;
    }
    if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
        fprintf(stderr, "DNS listen socket failed\n");
        return -1;
    }
    now = picoquic_current_time();
    for (i = 1; i < count; i++) {
        slipstream_server_stream_ctx_t* stream = streams[i];
        slipstream_server_ctx_t* ctx = stream->owner;
        short events = fds[i].revents;
        if (stream->connecting && now >= stream->connect_deadline) {
            fprintf(stderr, "Upstream connect timed out on stream %llu\n",
                (unsigned long long)stream->stream_id);
            slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_FILE_CANCEL_ERROR);
            continue;
        }
        if (events == 0) {
            continue;
        }
        if (events & POLLNVAL) {
            slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_INTERNAL_ERROR);
            continue;
        }
        if (stream->connecting) {
            int error = 0;
            socklen_t error_len = sizeof(error);
            if (getsockopt(stream->fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error != 0) {
                if (error != 0) {
                    errno = error;
                }
                perror("connect() failed");
                slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_FILE_CANCEL_ERROR);
                continue;
            }
            stream->connecting = false;
        }
        if (slipstream_server_flush(stream) != 0) {
            slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_FILE_CANCEL_ERROR);
            continue;
        }
        if (slipstream_server_stream_done(stream)) {
            slipstream_server_free_stream_context(ctx, stream);
            continue;
        }
        if (!stream->send_fin && (events & (POLLIN | POLLHUP | POLLERR))) {
            stream->read_wait = false;
            if (picoquic_mark_active_stream(ctx->cnx, stream->stream_id, 1, stream) != 0) {
                slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_INTERNAL_ERROR);
            }
        }
    }
    return 0;
}

int slipstream_server_sockloop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
                                       void* callback_ctx, void* callback_arg) {
    slipstream_server_ctx_t* default_ctx = callback_ctx;
    if (cb_mode != picoquic_packet_loop_before_select) {
        return 0;
    }
    if (should_shutdown) {
        /* A DNS server cannot send a close without a pending query. Do not
         * wait indefinitely for a disappearing client to poll during shutdown. */
        return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
    }
    /* Without DNS queries, prepare_packet is never called and PicoQUIC's
     * sender-side idle check does not run. Reap abandoned connections here,
     * between batches, when no DNS slot retains a connection pointer.
     * These deadlines mirror the pinned PicoQUIC check_idle_timer(). */
    uint64_t now = picoquic_current_time();
    picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic);
    while (cnx != NULL) {
        picoquic_cnx_t* next = picoquic_get_next_cnx(cnx);
        uint64_t deadline;
        if (cnx->cnx_state >= picoquic_state_ready) {
            uint64_t rto = picoquic_current_retransmit_timer(cnx, cnx->path[0]);
            uint64_t interval = MAX(cnx->idle_timeout, 3 * rto);
            deadline = cnx->latest_receive_time + interval;
            if (deadline < interval) {
                deadline = UINT64_MAX;
            }
        } else {
            uint64_t interval = quic->default_handshake_timeout;
            if (interval == 0) {
                interval = cnx->local_parameters.max_idle_timeout > 0 ?
                    cnx->local_parameters.max_idle_timeout * 1000ULL : PICOQUIC_MICROSEC_HANDSHAKE_MAX;
            }
            deadline = cnx->start_time + interval;
        }
        if (cnx->cnx_state == picoquic_state_disconnected || now >= deadline) {
            cnx->local_error = PICOQUIC_ERROR_IDLE_TIMEOUT;
            picoquic_connection_disconnect(cnx);
            picoquic_delete_cnx(cnx);
        }
        cnx = next;
    }
    return slipstream_server_poll(default_ctx, callback_arg);
}

int slipstream_server_callback(picoquic_cnx_t* cnx,
                               uint64_t stream_id, uint8_t* bytes, size_t length,
                               picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx) {
    slipstream_server_ctx_t* server_ctx = callback_ctx;
    slipstream_server_stream_ctx_t* stream_ctx = v_stream_ctx;
    slipstream_server_ctx_t* default_ctx = picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
    if (server_ctx == NULL || server_ctx == default_ctx) {
        if (default_ctx == NULL) {
            return -1;
        }
        server_ctx = calloc(1, sizeof(*server_ctx));
        if (server_ctx == NULL) {
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        server_ctx->upstream_addr = default_ctx->upstream_addr;
        server_ctx->cnx = cnx;
        server_ctx->next_ctx = default_ctx->next_ctx;
        server_ctx->prev_ctx = default_ctx;
        if (server_ctx->next_ctx != NULL) {
            server_ctx->next_ctx->prev_ctx = server_ctx;
        }
        default_ctx->next_ctx = server_ctx;
        picoquic_set_callback(cnx, slipstream_server_callback, server_ctx);
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (stream_ctx == NULL) {
            /* reset/stop_sending clear app_stream_ctx in this PicoQUIC revision.
             * Late peer data must not resurrect an aborted TCP connection. */
            picoquic_stream_head_t* quic_stream = picoquic_find_stream(cnx, stream_id);
            if (quic_stream == NULL || quic_stream->reset_requested || quic_stream->stop_sending_requested) {
                return 0;
            }
            stream_ctx = slipstream_server_create_stream_ctx(server_ctx, stream_id);
            if (stream_ctx == NULL) {
                (void)picoquic_stop_sending(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
            if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
                slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
        }
        if (stream_ctx->peer_fin) {
            return 0;
        }
        /* Flush older bytes first, then append without blocking the QUIC loop. */
        if (slipstream_server_flush(stream_ctx) != 0 ||
            slipstream_server_queue(stream_ctx, bytes, length) != 0) {
            slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_FILE_CANCEL_ERROR);
            return 0;
        }
        if (fin_or_event == picoquic_callback_stream_fin) {
            stream_ctx->peer_fin = true;
        }
        if (slipstream_server_flush(stream_ctx) != 0) {
            slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_FILE_CANCEL_ERROR);
        } else if (slipstream_server_stream_done(stream_ctx)) {
            slipstream_server_free_stream_context(server_ctx, stream_ctx);
        }
        break;
    case picoquic_callback_stop_sending:
    case picoquic_callback_stream_reset:
        if (stream_ctx != NULL) {
            slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_FILE_CANCEL_ERROR);
        } else {
            (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close:
    case picoquic_callback_application_close:
        /* No callback or worker can retain the connection after teardown. */
        picoquic_set_callback(cnx, NULL, NULL);
        slipstream_server_free_context(server_ctx);
        break;
    case picoquic_callback_prepare_to_send:
        if (stream_ctx == NULL || stream_ctx->connecting || stream_ctx->send_fin) {
            (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
            return 0;
        }
        if (length == 0) {
            (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 1);
            return 0;
        }
        /* Read first and advertise only the bytes actually received. FIONREAD
         * followed by recv could previously advertise more than a short read. */
        uint8_t data[16384];
        ssize_t n;
        do {
            n = recv(stream_ctx->fd, data, MIN(length, sizeof(data)), 0);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            int error = errno;
            (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
            if (error == EAGAIN || error == EWOULDBLOCK) {
                stream_ctx->read_wait = true;
            } else {
                errno = error;
                perror("recv() failed");
                slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_FILE_CANCEL_ERROR);
            }
            return 0;
        }
        uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, (size_t)n, n == 0, n > 0);
        if (buffer == NULL) {
            slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_INTERNAL_ERROR);
            return 0;
        }
        if (n > 0) {
            memcpy(buffer, data, (size_t)n);
        } else {
            /* TCP EOF closes only the server's sending direction. Keep the
             * context for peer data/FIN until its write direction also closes. */
            stream_ctx->send_fin = true;
            stream_ctx->read_wait = false;
            if (slipstream_server_stream_done(stream_ctx)) {
                slipstream_server_free_stream_context(server_ctx, stream_ctx);
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

int picoquic_slipstream_server(int server_port, bool listen_ipv6, const struct sockaddr_storage* listen_address,
                               const char* server_cert, const char* server_key,
                               struct sockaddr_storage* target_address, const char* domain_name) {
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    uint64_t current_time = 0;
    slipstream_server_ctx_t default_context = {0};

    // Store the target address directly - no need to resolve it here anymore
    memcpy(&default_context.upstream_addr, target_address, sizeof(struct sockaddr_storage));

    server_domain_name = strdup(domain_name);
    server_domain_name_len = strlen(domain_name);

    // int mtu = 250;
    int mtu = 900;

    /* Create config */
    picoquic_quic_config_t config;
    picoquic_config_init(&config);
    config.nb_connections = 8;
    config.server_cert_file = server_cert;
    config.server_key_file = server_key;
    // config.log_file = "-";
#ifdef BUILD_LOGLIB
    config.qlog_dir = SLIPSTREAM_QLOG_DIR;
#endif
    config.server_port = server_port;
    config.mtu_max = mtu;
    config.initial_send_mtu_ipv4 = mtu;
    config.initial_send_mtu_ipv6 = mtu;
    config.multipath_option = 1;
    config.use_long_log = 1;
    config.do_preemptive_repeat = 1;
    config.disable_port_blocking = 1;
    config.enable_sslkeylog = 1;
    config.alpn = SLIPSTREAM_ALPN;


    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    picoquic_quic_t* quic = picoquic_create_and_configure(&config, slipstream_server_callback, &default_context, current_time, NULL);
    if (quic == NULL) {
        DBG_PRINTF("Could not create server context", NULL);
        free(server_domain_name);
        server_domain_name = NULL;
        return -1;
    }

    picoquic_set_cookie_mode(quic, 0);
    picoquic_set_default_priority(quic, 2);
#ifdef BUILD_LOGLIB
    picoquic_set_qlog(quic, config.qlog_dir);
    debug_printf_push_stream(stderr);
#endif
    picoquic_set_key_log_file_from_env(quic);
    // picoquic_set_textlog(quic, "-");
    // picoquic_set_log_level(quic, 1);

    picoquic_set_default_congestion_algorithm(quic, slipstream_server_cc_algorithm);

    picoquic_packet_loop_param_t param = {0};
    if (listen_address != NULL) {
        param.local_af = listen_address->ss_family;
    } else if (listen_ipv6) {
        param.local_af = AF_INET6;
    } else {
        param.local_af = AF_INET;
    }
    param.local_port = server_port;
    param.do_not_use_gso = 1; // can't use GSO since we're limited to responding to one DNS query at a time
    param.is_client = 0;
    param.decode = server_decode;
    param.encode = server_encode;
    // param.delay_max = 5000;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.quic = quic;
    thread_ctx.param = &param;
    thread_ctx.loop_callback = slipstream_server_sockloop_callback;
    thread_ctx.loop_callback_ctx = &default_context;

    signal(SIGTERM, server_sighandler);
    signal(SIGINT, server_sighandler);
    // picoquic_packet_loop_v3(&thread_ctx);
    slipstream_packet_loop(&thread_ctx, listen_address);
    ret = thread_ctx.return_code;
    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        ret = 0;
    }

    /* And finish. */
    DBG_PRINTF("Server exit, ret = %d", ret);

    /* Also cover packet-loop errors: PicoQUIC does not promise a close
     * callback for every connection when its entire context is freed. */
    while (default_context.next_ctx != NULL) {
        slipstream_server_ctx_t* ctx = default_context.next_ctx;
        picoquic_set_callback(ctx->cnx, NULL, NULL);
        slipstream_server_free_context(ctx);
    }
    free(default_context.poll_fds);
    free(default_context.poll_streams);
    picoquic_free(quic);
    free(server_domain_name);
    server_domain_name = NULL;

    return ret;
}

