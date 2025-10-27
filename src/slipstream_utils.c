#include "slipstream_utils.h"

#include <picoquic_internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "picoquic_utils.h"


char* picoquic_connection_id_to_string(const picoquic_connection_id_t* cid) {
    // Each byte needs 2 hex characters + null terminator
    char* str = malloc((cid->id_len * 2 + 1) * sizeof(char));
    if (str == NULL) {
        return NULL;
    }

    // Convert each byte to hex
    for (int i = 0; i < cid->id_len; i++) {
        sprintf(&str[i * 2], "%02x", cid->id[i]);
    }
    str[cid->id_len * 2] = '\0';

    return str;
}

// Function to create a dummy sockaddr_storage with hardcoded IPv4 and port
void sockaddr_dummy(struct sockaddr_storage *addr_storage) {
    // Clear the entire sockaddr_storage to avoid residual data
    memset(addr_storage, 0, sizeof(struct sockaddr_storage));

    // Cast sockaddr_storage to sockaddr_in for IPv4
    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr_storage;

    // Set address family to AF_INET (IPv4)
    addr4->sin_family = AF_INET;

    // Use a hardcoded IPv4 address: 192.0.2.1 (TEST-NET-1 for testing)
    inet_pton(AF_INET, "192.0.2.1", &addr4->sin_addr);

    // Set a hardcoded port: 12345
    addr4->sin_port = htons(12345);

#ifdef __APPLE__ // For BSD systems, set sin_len
    addr4->sin_len = sizeof(struct sockaddr_in);
#endif
}

void print_sockaddr_ip_and_port(struct sockaddr_storage *addr_storage) {
    char ip_str[INET6_ADDRSTRLEN];
    int port;

    if (addr_storage->ss_family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr_storage;
        inet_ntop(AF_INET, &addr4->sin_addr, ip_str, INET6_ADDRSTRLEN);
        port = ntohs(addr4->sin_port);
    } else if (addr_storage->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr_storage;
        inet_ntop(AF_INET6, &addr6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
        port = ntohs(addr6->sin6_port);
    } else {
        DBG_PRINTF("Unknown address family", NULL);
        return;
    }

    DBG_PRINTF("%s:%d", ip_str, port);
}

bool slipstream_parse_host_port(const char* input, char* host_out, size_t host_out_len, int* port_out, int default_port) {
    if (input == NULL || host_out == NULL || host_out_len == 0 || port_out == NULL || default_port <= 0 || default_port > 65535) {
        return false;
    }

    *port_out = default_port;

    if (input[0] == '[') {
        const char* closing = strchr(input, ']');
        if (closing == NULL) {
            return false;
        }
        size_t host_len = (size_t)(closing - input - 1);
        if (host_len == 0 || host_len >= host_out_len) {
            return false;
        }
        memcpy(host_out, input + 1, host_len);
        host_out[host_len] = '\0';

        if (closing[1] == '\0') {
            return true;
        }
        if (closing[1] != ':') {
            return false;
        }

        const char* port_str = closing + 2;
        if (*port_str == '\0') {
            return false;
        }
        char* endptr = NULL;
        long parsed = strtol(port_str, &endptr, 10);
        if (*endptr != '\0') {
            return false;
        }
        if (parsed <= 0 || parsed > 65535) {
            return false;
        }
        *port_out = (int)parsed;
        return true;
    }

    const char* first_colon = strchr(input, ':');
    const char* last_colon = strrchr(input, ':');
    if (first_colon != NULL && first_colon == last_colon) {
        // Single colon: treat as host:port
        size_t host_len = (size_t)(last_colon - input);
        if (host_len == 0 || host_len >= host_out_len) {
            return false;
        }
        memcpy(host_out, input, host_len);
        host_out[host_len] = '\0';

        const char* port_str = last_colon + 1;
        if (*port_str == '\0') {
            return false;
        }
        char* endptr = NULL;
        long parsed = strtol(port_str, &endptr, 10);
        if (*endptr != '\0') {
            return false;
        }
        if (parsed <= 0 || parsed > 65535) {
            return false;
        }
        *port_out = (int)parsed;
        return true;
    }

    size_t input_len = strlen(input);
    if (input_len == 0 || input_len >= host_out_len) {
        return false;
    }
    memcpy(host_out, input, input_len + 1);
    *port_out = default_port;
    return true;
}
