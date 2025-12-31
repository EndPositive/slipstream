#include <assert.h>
#include <string>
#include <vector>

#include <stdarg.h>
#include <sys/socket.h>

#include "slipstream.h"
#include "slipstream_utils.h"

static std::vector<std::string> recorded_names;
static std::vector<int> recorded_ports;
static bool resolver_should_fail = false;
static int client_return_code = 0;
static int server_return_code = 0;
static int client_call_count = 0;
static int server_call_count = 0;

extern "C" void debug_printf(const char* fmt, ...) {
    (void)fmt;
    va_list args;
    va_start(args, fmt);
    va_end(args);
}

extern "C" int test_picoquic_get_server_address(const char* server_name, int server_port,
    struct sockaddr_storage* addr, int* is_name) {
    recorded_names.emplace_back(server_name);
    recorded_ports.push_back(server_port);
    if (resolver_should_fail) {
        return -1;
    }
    *is_name = 0;
    addr->ss_family = AF_INET;
    return 0;
}

extern "C" int test_picoquic_slipstream_client(int listen_port, struct st_address_t* server_addresses,
    size_t server_address_count, const char* domain_name, const char* cc_algo_id,
    bool gso, size_t keep_alive_interval) {
    (void)listen_port;
    (void)server_addresses;
    (void)server_address_count;
    (void)domain_name;
    (void)cc_algo_id;
    (void)gso;
    (void)keep_alive_interval;
    client_call_count++;
    return client_return_code;
}

extern "C" int test_picoquic_slipstream_server(int server_port, bool listen_ipv6, const char* pem_cert, const char* pem_key,
    struct sockaddr_storage* target_address, const char* domain_name) {
    (void)server_port;
    (void)listen_ipv6;
    (void)pem_cert;
    (void)pem_key;
    (void)target_address;
    (void)domain_name;
    server_call_count++;
    return server_return_code;
}
#define picoquic_get_server_address test_picoquic_get_server_address
#define picoquic_slipstream_client test_picoquic_slipstream_client
#define picoquic_slipstream_server test_picoquic_slipstream_server

#define main slipstream_client_cli_main
#include "../src/slipstream_client_cli.cpp"
#undef main

#define main slipstream_server_cli_main
#include "../src/slipstream_server_cli.cpp"
#undef main

#undef picoquic_get_server_address
#undef picoquic_slipstream_client
#undef picoquic_slipstream_server

static void reset_cli_state(void) {
    recorded_names.clear();
    recorded_ports.clear();
    resolver_should_fail = false;
    client_return_code = 0;
    server_return_code = 0;
    client_call_count = 0;
    server_call_count = 0;
}

static void client_cli_success_parses_resolvers(void) {
    reset_cli_state();
    client_return_code = 7;

    const char* argv_raw[] = {
        "slipstream-client",
        "--domain", "example.com",
        "--resolver", "1.2.3.4:5300",
        "--resolver", "[2001:db8::1]"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_client_cli_main(argc, argv);
    assert(rc == client_return_code);

    assert(client_call_count == 1);
    assert(recorded_names.size() == 2);
    assert(recorded_names[0] == "1.2.3.4");
    assert(recorded_ports[0] == 5300);
    assert(recorded_names[1] == "2001:db8::1");
    assert(recorded_ports[1] == 53);
}

static void client_cli_rejects_bad_resolver(void) {
    reset_cli_state();

    const char* argv_raw[] = {
        "slipstream-client",
        "--domain", "example.com",
        "--resolver", "bad:99999"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_client_cli_main(argc, argv);
    assert(rc == 1);

    assert(client_call_count == 0);
    assert(recorded_names.empty());
}

static void client_cli_handles_resolve_failure(void) {
    reset_cli_state();
    resolver_should_fail = true;

    const char* argv_raw[] = {
        "slipstream-client",
        "--domain", "example.com",
        "--resolver", "8.8.8.8"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_client_cli_main(argc, argv);
    assert(rc == 1);

    assert(client_call_count == 0);
    assert(recorded_names.size() == 1);
    assert(recorded_names[0] == "8.8.8.8");
}

static void client_cli_requires_domain(void) {
    reset_cli_state();

    const char* argv_raw[] = {
        "slipstream-client",
        "--resolver", "1.1.1.1"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_client_cli_main(argc, argv);
    assert(rc == 1);
    assert(client_call_count == 0);
}

static void client_cli_requires_resolver(void) {
    reset_cli_state();

    const char* argv_raw[] = {
        "slipstream-client",
        "--domain", "example.com"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_client_cli_main(argc, argv);
    assert(rc == 1);
    assert(client_call_count == 0);
}

static void client_cli_rejects_malformed_ipv6(void) {
    reset_cli_state();

    const char* argv_raw[] = {
        "slipstream-client",
        "--domain", "example.com",
        "--resolver", "[2001:db8::1"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_client_cli_main(argc, argv);
    assert(rc == 1);
    assert(client_call_count == 0);
}

static void server_cli_success_parses_target(void) {
    reset_cli_state();
    server_return_code = 11;

    const char* argv_raw[] = {
        "slipstream-server",
        "--domain", "example.com",
        "--target-address", "[2001:db8::2]:6500"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_server_cli_main(argc, argv);
    assert(rc == server_return_code);

    assert(server_call_count == 1);
    assert(recorded_names.size() == 1);
    assert(recorded_names[0] == "2001:db8::2");
    assert(recorded_ports[0] == 6500);
}

static void server_cli_rejects_bad_target(void) {
    reset_cli_state();

    const char* argv_raw[] = {
        "slipstream-server",
        "--domain", "example.com",
        "--target-address", "example.com:99999"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_server_cli_main(argc, argv);
    assert(rc == 1);

    assert(server_call_count == 0);
}

static void server_cli_handles_resolve_failure(void) {
    reset_cli_state();
    resolver_should_fail = true;

    const char* argv_raw[] = {
        "slipstream-server",
        "--domain", "example.com",
        "--target-address", "10.0.0.5:6500"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_server_cli_main(argc, argv);
    assert(rc == 1);

    assert(server_call_count == 0);
    assert(recorded_names.size() == 1);
    assert(recorded_names[0] == "10.0.0.5");
}

static void server_cli_uses_default_target(void) {
    reset_cli_state();
    server_return_code = 13;

    const char* argv_raw[] = {
        "slipstream-server",
        "--domain", "example.com"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_server_cli_main(argc, argv);
    assert(rc == server_return_code);
    assert(server_call_count == 1);
    assert(recorded_names.size() == 1);
    assert(recorded_names[0] == "127.0.0.1");
    assert(recorded_ports[0] == 5201);
}

static void server_cli_rejects_malformed_target(void) {
    reset_cli_state();

    const char* argv_raw[] = {
        "slipstream-server",
        "--domain", "example.com",
        "--target-address", "[2001:db8::2"
    };
    int argc = sizeof(argv_raw) / sizeof(argv_raw[0]);
    char** argv = const_cast<char**>(argv_raw);

    int rc = slipstream_server_cli_main(argc, argv);
    assert(rc == 1);
    assert(server_call_count == 0);
}

int main() {
    client_cli_success_parses_resolvers();
    client_cli_rejects_bad_resolver();
    client_cli_handles_resolve_failure();
    client_cli_requires_domain();
    client_cli_requires_resolver();
    client_cli_rejects_malformed_ipv6();
    server_cli_success_parses_target();
    server_cli_rejects_bad_target();
    server_cli_handles_resolve_failure();
    server_cli_uses_default_target();
    server_cli_rejects_malformed_target();
    return 0;
}
