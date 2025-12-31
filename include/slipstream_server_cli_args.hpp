#ifndef SLIPSTREAM_SERVER_CLI_ARGS_HPP
#define SLIPSTREAM_SERVER_CLI_ARGS_HPP

#include <string>

#include "slipstream_quick_arg_parser.hpp"

struct ServerArgs : MainArguments<ServerArgs> {
    using MainArguments<ServerArgs>::MainArguments;

    int listen_port = option("dns-listen-port", 'l', "DNS listen port (default: 53)") = 53;
    bool listen_ipv6 = option("dns-listen-ipv6", '6', "DNS listen on IPv6 (default: false)") = false;
    std::string target_address = option("target-address", 'a', "Target server address (default: 127.0.0.1:5201)") = "127.0.0.1:5201";
    std::string cert = option("cert", 'c', "Certificate file path (default: certs/cert.pem)") = "certs/cert.pem";
    std::string key = option("key", 'k', "Private key file path (default: certs/key.pem)") = "certs/key.pem";
    std::string domain = option("domain", 'd', "Domain name this server is authoritative for (Required)");

    static std::string help(const std::string& program_name);
    static const std::string version;
};

#endif // SLIPSTREAM_SERVER_CLI_ARGS_HPP
