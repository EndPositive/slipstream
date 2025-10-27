#ifndef SLIPSTREAM_UTILS_H
#define SLIPSTREAM_UTILS_H

#include <stdbool.h>
#include <stddef.h>

#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

char* picoquic_connection_id_to_string(const picoquic_connection_id_t* cid);

void sockaddr_dummy(struct sockaddr_storage *addr_storage);

void print_sockaddr_ip_and_port(struct sockaddr_storage *addr_storage);

bool slipstream_parse_host_port(const char* input, char* host_out, size_t host_out_len, int* port_out, int default_port);

#ifdef __cplusplus
}
#endif

#endif //SLIPSTREAM_UTILS_H
