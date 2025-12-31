#include <iostream>
#include <picosocks.h>
#include "slipstream.h"
#include "slipstream_client_cli_args.hpp"
#include "slipstream_utils.h"

std::string ClientArgs::help(const std::string& program_name) {
    return "slipstream-client - A high-performance covert channel over DNS (client)\n\n"
           "Usage: " + program_name + " [options]";
}

const std::string ClientArgs::version = "slipstream-client 0.1";

static int run_client(int argc, char** argv) {
    int exit_code = 0;
    ClientArgs args(argc, argv);

    // Ensure output buffers are flushed immediately (useful for debugging/logging)
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check mandatory client arguments */
    if (args.domain.empty()) {
        std::cerr << "Client error: Missing required --domain option" << std::endl;
        return 1;
    }
    if (args.resolver.empty()) {
        std::cerr << "Client error: Missing required --resolver option (at least one required)" << std::endl;
        return 1;
    }

    // Process resolver addresses
    std::vector<st_address_t> resolver_addresses;
    bool ipv4 = false;
    bool ipv6 = false;
    for (const auto& res_str : args.resolver) {
        st_address_t addr = {};
        char server_name[256];
        int server_port = 53;

        if (!slipstream_parse_host_port(res_str.c_str(), server_name, sizeof(server_name), &server_port, 53)) {
            std::cerr << "Invalid resolver address: " << res_str << std::endl;
            return 1;
        }

        int is_name = 0;
        if (picoquic_get_server_address(server_name, server_port, &addr.server_address, &is_name) != 0) {
            std::cerr << "Cannot resolve resolver address '" << server_name << "' port " << server_port << std::endl;
            return 1;
        }
        if (addr.server_address.ss_family == AF_INET) {
            ipv4 = true;
        } else if (addr.server_address.ss_family == AF_INET6) {
            ipv6 = true;
        } else {
            std::cerr << "Unsupported address family for resolver: " << res_str << std::endl;
            return 1;
        }
        addr.added = false;
        resolver_addresses.push_back(addr);
    }

    if (ipv4 && ipv6) {
        // due to single param.local_af in slipstream_client.c
        std::cerr << "Cannot mix IPv4 and IPv6 resolver addresses" << std::endl;
        exit(1);
    }

    exit_code = picoquic_slipstream_client(
        args.listen_port,
        resolver_addresses.data(),
        resolver_addresses.size(),
        (char*)args.domain.c_str(),
        (char*)args.congestion_control.c_str(),
        args.gso,
        args.keep_alive_interval
    );

    return exit_code;
}

int main(int argc, char** argv) {
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    int exit_code = run_client(argc, argv);

#ifdef _WINDOWS
    WSACleanup();
#endif
    return exit_code;
}
