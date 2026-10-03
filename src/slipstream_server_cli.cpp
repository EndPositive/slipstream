#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <picosocks.h>
#include "slipstream.h"
#include "quick_arg_parser.hpp"

struct ServerArgs : MainArguments<ServerArgs> {
    using MainArguments<ServerArgs>::MainArguments;

    int listen_port = option("dns-listen-port", 'l', "DNS listen port (default: 53)") = 53;
    std::string listen_address = option("dns-listen-address", 'b', "DNS listen IPv4/IPv6 literal (default: wildcard; overrides --dns-listen-ipv6)");
    bool listen_ipv6 = option("dns-listen-ipv6", '6', "DNS listen on IPv6 (default: false)") = false;
    std::string target_address = option("target-address", 'a', "Target server address (default: 127.0.0.1:5201)") = "127.0.0.1:5201";    std::string cert = option("cert", 'c', "Certificate file path (default: certs/cert.pem)") = "certs/cert.pem";
    std::string key = option("key", 'k', "Private key file path (default: certs/key.pem)") = "certs/key.pem";
    std::string domain = option("domain", 'd', "Domain name this server is authoritative for (Required)");

    static std::string help(const std::string& program_name) {
        return "slipstream-server - A high-performance covert channel over DNS (server)\n\n" 
               "Usage: " + program_name + " [options]";
    }

    static const std::string version;
};

const std::string ServerArgs::version = "slipstream-server 0.1";

/* Preflight file access so a missing PEM does not become an unexplained -1. */
static bool check_readable_file(const std::string& path, const char* description) {
    FILE* file = std::fopen(path.c_str(), "rb");
    if (file == NULL) {
        const int error = errno;
        std::cerr << "Error: unable to open " << description << " file: "
                  << path << ": " << std::strerror(error) << std::endl;
        return false;
    }
    std::fclose(file);
    return true;
}

int main(int argc, char** argv) {
    int exit_code = 0;
    ServerArgs args(argc, argv);

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    // Ensure output buffers are flushed immediately
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check mandatory server arguments */
    if (args.domain.empty()) {
        std::cerr << "Server error: Missing required --domain option" << std::endl;
        exit(1);
    }

    if (args.listen_port <= 0 || args.listen_port > 65535) {
        std::cerr << "Invalid DNS listen port: " << args.listen_port << std::endl;
        return 1;
    }

    struct sockaddr_storage dns_listen_address = {};
    const struct sockaddr_storage* dns_listen_address_ptr = NULL;
    if (!args.listen_address.empty()) {
        struct sockaddr_in* v4 = (struct sockaddr_in*)&dns_listen_address;
        struct sockaddr_in6* v6 = (struct sockaddr_in6*)&dns_listen_address;
        if (inet_pton(AF_INET, args.listen_address.c_str(), &v4->sin_addr) == 1) {
            v4->sin_family = AF_INET;
        } else if (inet_pton(AF_INET6, args.listen_address.c_str(), &v6->sin6_addr) == 1) {
            v6->sin6_family = AF_INET6;
        } else {
            std::cerr << "Invalid DNS listen address '" << args.listen_address
                      << "': expected an IPv4 or IPv6 literal (without a port)"
                      << std::endl;
            return 1;
        }
        dns_listen_address_ptr = &dns_listen_address;
    }

    const bool cert_readable = check_readable_file(args.cert, "certificate");
    const bool key_readable = check_readable_file(args.key, "private key");
    if (!cert_readable || !key_readable) {
        std::cerr << "Use --cert PATH and --key PATH to select readable PEM files."
                  << std::endl;
        return 1;
    }

    // Process target address
    struct sockaddr_storage target_address;
    char server_name[256];
    int server_port = 5201;

    if (sscanf(args.target_address.c_str(), "%255[^:]:%d", server_name, &server_port) < 1) {
        strncpy(server_name, args.target_address.c_str(), sizeof(server_name) - 1);
        server_name[sizeof(server_name) - 1] = '\0';
    }

    if (server_port <= 0 || server_port > 65535) {
        std::cerr << "Invalid port number in target address: " << args.target_address << std::endl;
        exit(1);
    }

    int is_name = 0;
    if (picoquic_get_server_address(server_name, server_port, &target_address, &is_name) != 0) {
        std::cerr << "Cannot resolve target address '" << server_name << "' port " << server_port << std::endl;
        exit(1);
    }

    exit_code = picoquic_slipstream_server(
        args.listen_port,
        args.listen_ipv6,
        dns_listen_address_ptr,
        (char*)args.cert.c_str(),
        (char*)args.key.c_str(),
        &target_address,
        (char*)args.domain.c_str()
    );

#ifdef _WINDOWS
    WSACleanup();
#endif

    exit(exit_code);
}
