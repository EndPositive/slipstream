#ifndef SLIPSTREAM_UTILS_H
#define SLIPSTREAM_UTILS_H

#include "picoquic.h"

char* picoquic_connection_id_to_string(const picoquic_connection_id_t* cid);

void sockaddr_dummy(struct sockaddr_storage *addr_storage);

void print_sockaddr_ip_and_port(struct sockaddr_storage *addr_storage);

char* to_uppercase(const char* str, size_t len);

#endif //SLIPSTREAM_UTILS_H
