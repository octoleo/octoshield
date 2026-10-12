/* SPDX-License-Identifier: Apache-2.0 */
#define main monitor_program_main
#include "../src/monitor.c"
#undef main
#include <assert.h>

static int parse_string(struct parser *parser, const char *text)
{
    int result = -1;
    for (size_t index = 0; text[index] != '\0'; index++) {
        int category = parse_byte(parser, (unsigned char)text[index]);
        if (category >= 0) result = category;
    }
    return result;
}

int main(void)
{
    struct category categories[CATEGORY_COUNT];
    categories_init(categories);
    /* Thresholds and category isolation. A monotonic timestamp of zero is valid. */
    for (unsigned index = 0; index < 4; index++) assert(!observe(&categories[0], 0));
    assert(observe(&categories[0], 0));
    assert(categories[0].alerts == 1 && categories[2].alerts == 0);
    assert(observe(&categories[1], 0));
    assert(!observe(&categories[1], 299));
    assert(observe(&categories[1], 300));
    /* Window expiry does not accumulate indefinitely spaced events. */
    for (unsigned index = 0; index < 8; index++) assert(!observe(&categories[2], index * 60));
    for (unsigned index = 0; index < 3; index++) assert(!observe(&categories[2], 421));
    assert(observe(&categories[2], 421));
    for (unsigned index = 0; index < 100; index++) assert(!observe(&categories[2], 422));
    assert(categories[2].alerts == 1);
    /* Saturation cannot wrap a counter and defeat rate limiting. */
    categories[2].count = UINT_MAX;
    assert(!observe(&categories[2], 423));
    assert(categories[2].count == UINT_MAX);
    struct parser parser = {{0}, 0, false};
    assert(parse_string(&parser, "firewall\n") == 0);
    assert(parse_string(&parser, "usb\n") == 1);
    assert(parse_string(&parser, "auth\n") == 2);
    assert(parse_string(&parser, "unknown\n") == -1);
    assert(parse_string(&parser, " auth\n") == -1);
    assert(parse_string(&parser, "auth\r\n") == -1);
    assert(parse_string(&parser, "auth") == -1);
    assert(parse_byte(&parser, 0) == -1);
    assert(parse_byte(&parser, '\n') == -1);
    for (unsigned index = 0; index < 100000; index++) assert(parse_byte(&parser, 'a') == -1);
    assert(parse_string(&parser, "usb\n") == -1);
    assert(parse_string(&parser, "usb\n") == 1);
    puts("monitor C tests passed");
    return 0;
}
