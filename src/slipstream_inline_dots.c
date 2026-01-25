#include "slipstream_inline_dots.h"

size_t slipstream_inline_dotify(char * __restrict__ buf, size_t buflen, size_t len) {
    if (len == 0) { // If there's nothing to do, we do nothing. Efficient, right?
        if (buflen > 0) buf[0] = '\0';
        return 0;
    }

    size_t dots = len / 57;             // Every 57 bytes, a dot. It's the law.
    size_t new_len = len + dots;

    if (new_len + 1 > buflen) {
        return (size_t)-1;              // Err -> .h? Meh.
    }

    buf[new_len] = '\0';                // Amen.

    char *src = buf + len - 1;          // Points to last char of original string
    char *dst = buf + new_len - 1;      // Points to where last char will end up

    // Avoid modulo operation in tight loop
    size_t next_dot = len - (len % 57);

    size_t current_pos = len;

    // Move characters right-to-left, inserting dots
    while (current_pos > 0) {
        if (current_pos == next_dot && next_dot != len) {
            *dst-- = '.';               // Dot. Because rules are rules, even for dots.
            next_dot -= 57;             // Next dot is 57 chars back.
            current_pos--;              // Account for the char space the dot took.
            continue;                   // Skip the copy for this iteration, already placed dot.
        }
        *dst-- = *src--;
        current_pos--;
    }

    return new_len;
}

size_t slipstream_inline_undotify(char * __restrict__ buf, size_t len) {
    char *reader = buf;
    char *writer = buf;

    for (size_t i = 0; i < len; ++i) {
        char c = *reader++;
        if (c != '.')
            *writer++ = c;              // Filter out the noise. Only the good stuff.
    }

    *writer = '\0';                     // Rewind the tape. The future is clean.
    return writer - buf;
}
