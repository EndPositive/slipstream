#include <assert.h>
#include <string>

#include "slipstream_client_cli_args.hpp"
#include "slipstream_server_cli_args.hpp"

std::string ClientArgs::help(const std::string& program_name) {
    return "slipstream-client - A high-performance covert channel over DNS (client)\n\n"
           "Usage: " + program_name + " [options]";
}

const std::string ClientArgs::version = "slipstream-client 0.1";

std::string ServerArgs::help(const std::string& program_name) {
    return "slipstream-server - A high-performance covert channel over DNS (server)\n\n"
           "Usage: " + program_name + " [options]";
}

const std::string ServerArgs::version = "slipstream-server 0.1";

static void test_client_args_parses_valid_options() {
    const char* argv_raw[] = {
        "slipstream-client",
        "--domain", "example.com",
        "--resolver", "1.1.1.1:5300",
        "--resolver", "8.8.8.8",
        "--tcp-listen-port", "7000",
        "--congestion-control", "bbr",
        "-g",
        "--keep-alive-interval", "123"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    ClientArgs args(argc, argv);
    assert(args.domain == "example.com");
    assert(args.listen_port == 7000);
    assert(args.congestion_control == "bbr");
    assert(args.gso == true);
    assert(args.keep_alive_interval == 123);
    assert(args.resolver.size() == 2);
    assert(args.resolver[0] == "1.1.1.1:5300");
    assert(args.resolver[1] == "8.8.8.8");
}

static void test_client_args_defaults() {
    const char* argv_raw[] = {
        "slipstream-client",
        "--domain", "example.net",
        "--resolver", "9.9.9.9"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    ClientArgs args(argc, argv);
    assert(args.listen_port == 5201);
    assert(args.congestion_control == "dcubic");
    assert(args.gso == false);
    assert(args.keep_alive_interval == 400);
    assert(args.resolver.size() == 1);
}

static void test_server_args_parses_valid_options() {
    const char* argv_raw[] = {
        "slipstream-server",
        "--domain", "example.com",
        "--dns-listen-port", "8053",
        "--target-address", "10.0.0.5:6500",
        "--cert", "/tmp/cert.pem",
        "--key", "/tmp/key.pem"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    ServerArgs args(argc, argv);
    assert(args.listen_port == 8053);
    assert(args.target_address == "10.0.0.5:6500");
    assert(args.cert == "/tmp/cert.pem");
    assert(args.key == "/tmp/key.pem");
    assert(args.domain == "example.com");
}

static void test_server_args_defaults() {
    const char* argv_raw[] = {
        "slipstream-server",
        "--domain", "corp.internal"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    ServerArgs args(argc, argv);
    assert(args.listen_port == 53);
    assert(args.target_address == "127.0.0.1:5201");
    assert(args.cert == "certs/cert.pem");
    assert(args.key == "certs/key.pem");
}

static void test_client_args_missing_required_fields() {
    const char* argv_raw[] = {
        "slipstream-client"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    ClientArgs args(argc, argv);
    assert(args.domain.empty());
    assert(args.resolver.empty());
}

static void test_server_args_missing_required_domain() {
    const char* argv_raw[] = {
        "slipstream-server"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    ServerArgs args(argc, argv);
    assert(args.domain.empty());
}

int main() {
    test_client_args_parses_valid_options();
    test_client_args_defaults();
    test_server_args_parses_valid_options();
    test_server_args_defaults();
    test_client_args_missing_required_fields();
    test_server_args_missing_required_domain();
    return 0;
}
