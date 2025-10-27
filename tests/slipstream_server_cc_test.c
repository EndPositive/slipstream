#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "picoquic_internal.h"
#include "slipstream_server_cc.h"

static void test_slipstream_server_cc_init_and_delete(void) {
    picoquic_cnx_t cnx = {0};
    picoquic_path_t path = {0};

    slipstream_server_cc_algorithm->alg_init(&cnx, &path, 0);
    assert(path.congestion_alg_state != NULL);

    slipstream_server_cc_algorithm->alg_delete(&path);
    assert(path.congestion_alg_state == NULL);
}

static void test_slipstream_server_cc_notify_updates_fields(void) {
    picoquic_cnx_t cnx = {0};
    picoquic_path_t path = {0};

    slipstream_server_cc_algorithm->alg_init(&cnx, &path, 1234);
    assert(path.congestion_alg_state != NULL);

    path.cwin = 0;
    path.is_cc_data_updated = 0;

    slipstream_server_cc_algorithm->alg_notify(
        &cnx,
        &path,
        picoquic_congestion_notification_acknowledgement,
        NULL,
        5678);

    assert(path.is_cc_data_updated == 1);
    assert(path.cwin == UINT64_MAX);

    slipstream_server_cc_algorithm->alg_delete(&path);
}

static void test_slipstream_server_cc_observe_reports_state(void) {
    picoquic_cnx_t cnx = {0};
    picoquic_path_t path = {0};

    slipstream_server_cc_algorithm->alg_init(&cnx, &path, 42);

    uint64_t cc_state = 111;
    uint64_t cc_param = 0;
    slipstream_server_cc_algorithm->alg_observe(&path, &cc_state, &cc_param);

    assert(cc_state == 0);
    assert(cc_param == UINT64_MAX);

    slipstream_server_cc_algorithm->alg_delete(&path);
}

int main(void) {
    test_slipstream_server_cc_init_and_delete();
    test_slipstream_server_cc_notify_updates_fields();
    test_slipstream_server_cc_observe_reports_state();
    return 0;
}
