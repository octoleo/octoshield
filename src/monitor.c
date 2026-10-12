/* SPDX-License-Identifier: Apache-2.0
 * Bounded event aggregation. Only normalized category names cross this boundary;
 * raw journal text, device names and user names never reach desktop sessions.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CATEGORY_COUNT 3
#define WINDOW_SECONDS 60
#define COOLDOWN_SECONDS 300
#define HEARTBEAT_SECONDS 15

struct category {
    uint64_t window_start;
    uint64_t last_alert;
    uint64_t alerts;
    unsigned count;
    unsigned threshold;
    bool started;
    bool alerted;
};

struct parser {
    char line[16];
    size_t length;
    bool invalid;
};

static void categories_init(struct category categories[CATEGORY_COUNT])
{
    memset(categories, 0, sizeof(struct category) * CATEGORY_COUNT);
    categories[0].threshold = 5;
    categories[1].threshold = 1;
    categories[2].threshold = 5;
}

static bool observe(struct category *category, uint64_t now)
{
    if (!category->started || now < category->window_start ||
        now - category->window_start >= WINDOW_SECONDS) {
        category->window_start = now;
        category->count = 0;
        category->started = true;
    }
    if (category->count < UINT_MAX) {
        category->count++;
    }
    if (category->count < category->threshold ||
        (category->alerted && now >= category->last_alert &&
         now - category->last_alert < COOLDOWN_SECONDS)) {
        return false;
    }
    if (category->alerts < UINT64_MAX) {
        category->alerts++;
    }
    category->last_alert = now;
    category->alerted = true;
    category->window_start = now;
    category->count = 0;
    return true;
}

/* Reject an entire overlong, binary, unknown or unterminated record. */
static int parse_byte(struct parser *parser, unsigned char byte)
{
    int category = -1;
    if (byte != '\n') {
        if (byte < 'a' || byte > 'z' || parser->length >= sizeof(parser->line) - 1) {
            parser->invalid = true;
        } else if (!parser->invalid) {
            parser->line[parser->length++] = (char)byte;
        }
        return -1;
    }
    parser->line[parser->length] = '\0';
    if (!parser->invalid) {
        if (strcmp(parser->line, "firewall") == 0) category = 0;
        else if (strcmp(parser->line, "usb") == 0) category = 1;
        else if (strcmp(parser->line, "auth") == 0) category = 2;
    }
    parser->length = 0;
    parser->invalid = false;
    return category;
}

static uint64_t monotonic_seconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)now.tv_sec;
}

static int publish(int directory, const char *instance,
                   const struct category categories[CATEGORY_COUNT])
{
    char state[256];
    int length = snprintf(state, sizeof(state), "v1 %s %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                          instance, categories[0].alerts, categories[1].alerts,
                          categories[2].alerts);
    if (length < 0 || (size_t)length >= sizeof(state)) return -1;
    /* The directory is exclusively locked, owner-controlled and not writable
     * by anyone else. Remove a crash residue without following its target. */
    if (unlinkat(directory, "events.new", 0) != 0 && errno != ENOENT) return -1;
    int file = openat(directory, "events.new", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (file < 0) return -1;
    size_t offset = 0;
    while (offset < (size_t)length) {
        ssize_t written = write(file, state + offset, (size_t)length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            close(file);
            return -1;
        }
        offset += (size_t)written;
    }
    if (fchmod(file, 0644) != 0) {
        close(file);
        return -1;
    }
    if (close(file) != 0) return -1;
    return renameat(directory, "events.new", directory, "events");
}

int main(int argc, char **argv)
{
    if (argc != 3 || strcmp(argv[1], "--output-dir") != 0) {
        fprintf(stderr, "Usage: octoshield-monitor --output-dir DIRECTORY\n");
        return EXIT_FAILURE;
    }
    int directory = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    struct stat metadata;
    if (directory < 0 || fstat(directory, &metadata) != 0 ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 0022) != 0) {
        fprintf(stderr, "Monitor needs an owner-controlled directory without group/other write access.\n");
        if (directory >= 0) close(directory);
        return EXIT_FAILURE;
    }
    if (flock(directory, LOCK_EX | LOCK_NB) != 0) {
        perror("monitor already running or directory cannot be locked");
        close(directory);
        return EXIT_FAILURE;
    }
    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        perror("clock_gettime");
        close(directory);
        return EXIT_FAILURE;
    }
    char instance[96];
    snprintf(instance, sizeof(instance), "%ld-%ld-%ld", (long)started.tv_sec,
             started.tv_nsec, (long)getpid());
    struct category categories[CATEGORY_COUNT];
    categories_init(categories);
    struct parser parser = {{0}, 0, false};
    uint64_t last_publish = monotonic_seconds();
    if (publish(directory, instance, categories) != 0) goto failure;
    struct pollfd input = {STDIN_FILENO, POLLIN, 0};
    for (;;) {
        int ready = poll(&input, 1, 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) goto failure;
        uint64_t now = monotonic_seconds();
        bool changed = false;
        if (ready > 0) {
            if ((input.revents & (POLLERR | POLLNVAL)) != 0) goto failure;
            unsigned char buffer[4096];
            ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            /* EOF means an event producer was lost; let systemd restart it. */
            if (count <= 0) {
                fprintf(stderr, "Security event feed closed.\n");
                close(directory);
                return EXIT_FAILURE;
            }
            for (ssize_t index = 0; index < count; index++) {
                int category = parse_byte(&parser, buffer[index]);
                if (category >= 0 && observe(&categories[category], now)) changed = true;
            }
        }
        if (changed || now - last_publish >= HEARTBEAT_SECONDS) {
            if (publish(directory, instance, categories) != 0) goto failure;
            last_publish = now;
        }
    }
failure:
    perror("octoshield-monitor");
    close(directory);
    return EXIT_FAILURE;
}
