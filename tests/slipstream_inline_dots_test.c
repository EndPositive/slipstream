#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "slipstream_inline_dots.h"

static void fill_sequential(char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (char)('a' + (i % 26));
    }
    buf[len] = '\0';
}

static void test_dotify_zero_length(void) {
    char buffer[8] = "ignored";
    size_t written = slipstream_inline_dotify(buffer, sizeof buffer, 0);
    assert(written == 0);
    assert(buffer[0] == '\0');
}

static void test_dotify_no_dots_needed(void) {
    const size_t input_len = 10;
    char buffer[32];
    fill_sequential(buffer, input_len);

    char expected[32];
    memcpy(expected, buffer, input_len + 1);

    size_t written = slipstream_inline_dotify(buffer, sizeof buffer, input_len);
    assert(written == input_len);
    assert(strcmp(buffer, expected) == 0);
}

static void test_dotify_inserts_single_dot(void) {
    const size_t input_len = 57;
    char buffer[80];
    memset(buffer, 'A', input_len);
    buffer[input_len] = '\0';

    size_t written = slipstream_inline_dotify(buffer, sizeof buffer, input_len);
    assert(written == input_len + 1);
    assert(buffer[written] == '\0');
    assert(buffer[input_len] == '.');
    for (size_t i = 0; i < input_len; ++i) {
        assert(buffer[i] == 'A');
    }
}

static void test_dotify_inserts_multiple_dots(void) {
    const size_t input_len = 120;
    char buffer[160];
    fill_sequential(buffer, input_len);

    char original[160];
    memcpy(original, buffer, input_len + 1);

    size_t written = slipstream_inline_dotify(buffer, sizeof buffer, input_len);
    assert(written == input_len + (input_len / 57));
    assert(buffer[written] == '\0');

    size_t expected_dots = input_len / 57;
    size_t actual_dots = 0;
    for (size_t i = 0; i < written; ++i) {
        if (buffer[i] == '.') {
            ++actual_dots;
            assert(i == 0 || buffer[i - 1] != '.');
        } else {
            if (i == 0) {
                assert(buffer[i] != '.');
            }
        }
    }
    assert(actual_dots == expected_dots);

    size_t undot_len = slipstream_inline_undotify(buffer, written);
    assert(undot_len == input_len);
    assert(strcmp(buffer, original) == 0);
}

static void test_dotify_buffer_too_small(void) {
    const size_t input_len = 57;
    char buffer[58];
    memset(buffer, 'Z', input_len);
    buffer[input_len] = '\0';

    size_t written = slipstream_inline_dotify(buffer, sizeof buffer, input_len);
    assert(written == (size_t)-1);
    assert(buffer[input_len] == '\0');
}

static void test_undotify_removes_dots(void) {
    char buffer[] = "abc.def.ghi";
    size_t new_len = slipstream_inline_undotify(buffer, strlen(buffer));
    assert(new_len == strlen("abcdefghi"));
    assert(strcmp(buffer, "abcdefghi") == 0);
}

static void test_dotify_undotify_roundtrip(void) {
    const size_t input_len = 200;
    char buffer[256];
    fill_sequential(buffer, input_len);

    char original[256];
    memcpy(original, buffer, input_len + 1);

    size_t dotted_len = slipstream_inline_dotify(buffer, sizeof buffer, input_len);
    assert(dotted_len != (size_t)-1);

    size_t undotted_len = slipstream_inline_undotify(buffer, dotted_len);
    assert(undotted_len == input_len);
    assert(strcmp(buffer, original) == 0);
}

int main(void) {
    test_dotify_zero_length();
    test_dotify_no_dots_needed();
    test_dotify_inserts_single_dot();
    test_dotify_inserts_multiple_dots();
    test_dotify_buffer_too_small();
    test_undotify_removes_dots();
    test_dotify_undotify_roundtrip();
    return 0;
}
