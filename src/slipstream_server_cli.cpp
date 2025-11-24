#include <iostream>
#include <picosocks.h>
#include "slipstream.h"
#include "slipstream_server_cli_args.hpp"
#include "slipstream_utils.h"

std::string ServerArgs::help(const std::string& program_name) {
    return "slipstream-server - A high-performance covert channel over DNS (server)\n\n"
           "Usage: " + program_name + " [options]";
}

const std::string ServerArgs::version = "slipstream-server 0.1";

static int run_server(int argc, char** argv) {
    int exit_code = 0;
    ServerArgs args(argc, argv);

    // Ensure output buffers are flushed immediately
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check mandatory server arguments */
    if (args.domain.empty()) {
        std::cerr << "Server error: Missing required --domain option" << std::endl;
        return 1;
    }

    // Process target address
    struct sockaddr_storage target_address;
    char server_name[256];
    int server_port = 5201;

    if (!slipstream_parse_host_port(args.target_address.c_str(), server_name, sizeof(server_name), &server_port, 5201)) {
        std::cerr << "Invalid target address: " << args.target_address << std::endl;
        return 1;
    }

    int is_name = 0;
    if (picoquic_get_server_address(server_name, server_port, &target_address, &is_name) != 0) {
        std::cerr << "Cannot resolve target address '" << server_name << "' port " << server_port << std::endl;
        return 1;
    }

    exit_code = picoquic_slipstream_server(
        args.listen_port,
        (char*)args.cert.c_str(),
        (char*)args.key.c_str(),
        &target_address,
        (char*)args.domain.c_str()
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

    int exit_code = run_server(argc, argv);

#ifdef _WINDOWS
    WSACleanup();
#endif
    return exit_code;
}
