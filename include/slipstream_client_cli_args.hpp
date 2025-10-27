#ifndef SLIPSTREAM_CLIENT_CLI_ARGS_HPP
#define SLIPSTREAM_CLIENT_CLI_ARGS_HPP

#include <string>
#include <vector>

#include "slipstream_quick_arg_parser.hpp"

struct ClientArgs : MainArguments<ClientArgs> {
    using MainArguments<ClientArgs>::MainArguments;

    int listen_port = option("tcp-listen-port", 'l', "Listen port (default: 5201)") = 5201;
    std::vector<std::string> resolver = option("resolver", 'r', "Slipstream server resolver address (e.g., 1.1.1.1 or 8.8.8.8:53). Can be specified multiple times. (Required)");
    std::string congestion_control = option("congestion-control", 'c', "Congestion control algorithm (bbr, dcubic) (default: dcubic)") = "dcubic";
    bool gso = option('g', "GSO enabled (true/false) (default: false). Use --gso or --gso=true to enable.");
    std::string domain = option("domain", 'd', "Domain name used for the covert channel (Required)");
    int keep_alive_interval = option("keep-alive-interval", 't', "Send keep alive pings at this interval (default: 400, disabled: 0)") = 400;

    static std::string help(const std::string& program_name);
    static const std::string version;
};

#endif // SLIPSTREAM_CLIENT_CLI_ARGS_HPP
