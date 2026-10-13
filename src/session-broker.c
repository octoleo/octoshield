/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "ui/protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <json-glib/json-glib.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* This executable is the ONLY long-lived privileged desktop process. It has
 * no socket, token, shell command, or arbitrary executable interface. The
 * unprivileged GUI owns its anonymous pipes and must remain alive in the same
 * active, unlocked local graphical login session. */
#define BROKER_PATH "/usr/libexec/octoshield-session"
#define MAINTENANCE_PATH "/run/octoshield-package-maintenance"
#define HELPER_PATH "/usr/libexec/octoshield-helper"
#define RECORD_LIMIT 65536U
#define QUEUE_LIMIT (256U * 1024U)
#define OPERATION_LIMIT (30 * 60 * G_USEC_PER_SEC)
#define DRAIN_LIMIT (5 * 60 * G_USEC_PER_SEC)
#define BUS_TIMEOUT 2000

typedef struct {
    uid_t uid;
    pid_t parent;
    int parent_fd;
    GDBusConnection *bus;
    gchar *session;
    struct stat executable;
} Authority;

typedef struct {
    Authority authority;
    int input, output, child_input, child_output, child_error;
    pid_t child;
    guint64 request, next_request, prompt, last_prompt;
    gboolean revoked, output_alive, done_seen, done_success, child_exited;
    int child_status;
    gint64 started, revoked_at;
    GString *input_line, *child_line, *pending;
} Broker;

static void close_fd(int *fd)
{
    if (*fd >= 0) {
        (void)close(*fd);
        *fd = -1;
    }
}

static gboolean nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 &&
           fcntl(fd, F_SETFD, FD_CLOEXEC) == 0;
}

static gboolean json_member(JsonObject *object, const gchar *name, GType type)
{
    JsonNode *node = json_object_get_member(object, name);
    return node && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == type;
}

/* JSON-GLib accepts some JavaScript extensions and may wrap oversized ints.
 * Check framing, nesting and numeric range BEFORE handing it untrusted input. */
static gboolean record_bytes(const gchar *line, gsize length, guint *members)
{
    gboolean string = FALSE, escaped = FALSE;
    guint depth = 0;
    *members = 0;
    if (length == 0 || length > RECORD_LIMIT || !g_utf8_validate(line, (gssize)length, NULL))
        return FALSE;
    for (gsize i = 0; i < length; i++) {
        guchar c = (guchar)line[i];
        if (c == 0 || c == '\n' || c == '\r') return FALSE;
        if (string) {
            if (escaped) {
                if (length - i >= 5 && memcmp(line + i, "u0000", 5) == 0) return FALSE;
                escaped = FALSE;
           } else if (c == '\\') escaped = TRUE;
            else if (c == '"') string = FALSE;
            else if (c < 0x20) return FALSE;
        } else if (c == '"') string = TRUE;
        else if (c == '{' || c == '[') {
            if (++depth > 8) return FALSE;
        } else if (c == '}' || c == ']') {
            if (depth == 0) return FALSE;
            depth--;
         } else if (c == ':' && depth == 1) (*members)++;
        else if (c == ',') {
            gsize next = i + 1;
            while (next < length && g_ascii_isspace(line[next])) next++;
            if (next == length || line[next] == '}' || line[next] == ']') return FALSE;
        } else if (c == '/' || c == '\'' || c == '=' || c == ';') return FALSE;
        else if (c == '-' || g_ascii_isdigit(c)) {
            gsize end = i + 1;
            while (end < length && strchr("-+0123456789.eE", line[end])) end++;
            gchar *number = g_strndup(line + i, end - i), *tail = NULL;
            errno = 0;
            (void)g_ascii_strtoll(number, &tail, 10);
            gboolean valid = errno == 0 && tail != number && *tail == '\0' &&
                             !(number[0] == '0' && number[1] != '\0');
            g_free(number);
            if (!valid) return FALSE;
            i = end - 1;
        }
    }
    return !string && !escaped && depth == 0;
}

static JsonObject *parse_record(const gchar *line, gsize length)
{
    guint members = 0;
    if (!record_bytes(line, length, &members)) return NULL;
    JsonParser *parser = json_parser_new();
    JsonObject *object = NULL;
    if (json_parser_load_from_data(parser, line, (gssize)length, NULL)) {
        JsonNode *root = json_parser_get_root(parser);
        if (root && JSON_NODE_HOLDS_OBJECT(root) &&
            json_object_get_size(json_node_get_object(root)) == members)
            object = json_object_ref(json_node_get_object(root));
    }
    g_object_unref(parser);
    return object;
}

static gboolean queue_event(Broker *broker, JsonObject *object)
{
    if (!broker->output_alive) return FALSE;
    JsonNode *node = json_node_new(JSON_NODE_OBJECT);
    json_node_set_object(node, object);
    gchar *data = json_to_string(node, FALSE);
    gsize length = strlen(data);
    json_node_free(node);
    gboolean fits = length <= RECORD_LIMIT && broker->pending->len + length + 1 <= QUEUE_LIMIT;
    if (fits) {
        g_string_append_len(broker->pending, data, (gssize)length);
        g_string_append_c(broker->pending, '\n');
    }
    g_free(data);
    return fits;
}

static JsonObject *event_object(const gchar *type, guint64 request)
{
    JsonObject *object = json_object_new();
    json_object_set_string_member(object, "type", type);
    if (request) json_object_set_int_member(object, "request", (gint64)request);
    return object;
}

static void broker_revoke(Broker *broker, const gchar *reason)
{
    if (broker->revoked) return;
    broker->revoked = TRUE;
    broker->revoked_at = g_get_monotonic_time();
    broker->prompt = 0;
    close_fd(&broker->child_input);
    JsonObject *event = event_object("closed", 0);
    json_object_set_string_member(event, "reason", reason);
    /* A stalled GUI cannot retain privileged work or unbounded buffered logs. */
    g_string_truncate(broker->pending, 0);
    (void)queue_event(broker, event);
    json_object_unref(event);
}

static gboolean session_properties(GVariant *properties, uid_t uid)
{
    gboolean active = FALSE, remote = TRUE, locked = TRUE;
    guint32 user = 0;
    const gchar *type = NULL;
    GVariant *owner = g_variant_lookup_value(properties, "User", G_VARIANT_TYPE("(uo)"));
    if (owner) g_variant_get(owner, "(u&o)", &user, NULL);
    gboolean valid = owner && user == uid &&
        g_variant_lookup(properties, "Active", "b", &active) && active &&
        g_variant_lookup(properties, "Remote", "b", &remote) && !remote &&
        g_variant_lookup(properties, "LockedHint", "b", &locked) && !locked &&
        g_variant_lookup(properties, "Type", "&s", &type) &&
        (g_str_equal(type, "x11") || g_str_equal(type, "wayland"));
    if (owner) g_variant_unref(owner);
    return valid;
}

static gboolean session_valid(Authority *authority, const gchar *path)
{
    GVariant *result = g_dbus_connection_call_sync(authority->bus,
        "org.freedesktop.login1", path, "org.freedesktop.DBus.Properties", "GetAll",
        g_variant_new("(s)", "org.freedesktop.login1.Session"), G_VARIANT_TYPE("(a{sv})"),
        G_DBUS_CALL_FLAGS_NONE, BUS_TIMEOUT, NULL, NULL);
    if (!result) return FALSE;
    GVariant *properties = g_variant_get_child_value(result, 0);
    gboolean valid = session_properties(properties, authority->uid);
    g_variant_unref(properties);
    g_variant_unref(result);
    return valid;
}

static gboolean parent_alive(Authority *authority)
{
    struct pollfd fd = {.fd = authority->parent_fd, .events = POLLIN};
    int result;
    do { result = poll(&fd, 1, 0); } while (result < 0 && errno == EINTR);
    return result == 0;
}

static gboolean executable_matches(const struct stat *initial, const struct stat *current)
{
    return S_ISREG(current->st_mode) && current->st_uid == 0 &&
           (current->st_mode & 0022) == 0 && current->st_nlink > 0 &&
           current->st_ino == initial->st_ino && current->st_dev == initial->st_dev &&
           current->st_size == initial->st_size &&
           current->st_ctim.tv_sec == initial->st_ctim.tv_sec &&
           current->st_ctim.tv_nsec == initial->st_ctim.tv_nsec;
}

static gboolean deployment_valid(Authority *authority)
{
    struct stat marker, installed;
    errno = 0;
    if (lstat(MAINTENANCE_PATH, &marker) == 0 || errno != ENOENT) return FALSE;
    return lstat(BROKER_PATH, &installed) == 0 &&
           executable_matches(&authority->executable, &installed);
}

static gboolean authority_valid(Authority *authority)
{
    return getppid() == authority->parent && deployment_valid(authority) && parent_alive(authority) && !g_dbus_connection_is_closed(authority->bus) &&
           session_valid(authority, authority->session) && parent_alive(authority);
}

static gboolean session_bind(Authority *authority)
{
    GError *error = NULL;
    GVariant *result = g_dbus_connection_call_sync(authority->bus,
        "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
        "GetSessionByPID", g_variant_new("(u)", (guint32)authority->parent),
        G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE, BUS_TIMEOUT, NULL, &error);
    if (result) {
        g_variant_get(result, "(o)", &authority->session);
        g_variant_unref(result);
        /* A remote, locked, or inactive direct session must NEVER fall back. */
        return session_valid(authority, authority->session);
    }
    gchar *remote_error = error ? g_dbus_error_get_remote_error(error) : NULL;
    gboolean no_session = g_strcmp0(remote_error, "org.freedesktop.login1.NoSessionForPID") == 0;
    g_free(remote_error);
    g_clear_error(&error);
    if (!no_session) return FALSE;
    /* GNOME can put application processes in the per-user systemd slice,
     * outside session.scope. Bind one unambiguous active graphical session. */
    result = g_dbus_connection_call_sync(authority->bus,
        "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
        "ListSessions", NULL, G_VARIANT_TYPE("(a(susso))"), G_DBUS_CALL_FLAGS_NONE,
        BUS_TIMEOUT, NULL, NULL);
    if (!result) return FALSE;
    GVariant *sessions = g_variant_get_child_value(result, 0);
    GVariantIter iter;
    const gchar *id, *name, *seat, *path;
    guint32 uid;
    guint matches = 0, count = 0;
    g_variant_iter_init(&iter, sessions);
    while (g_variant_iter_loop(&iter, "(&su&s&s&o)", &id, &uid, &name, &seat, &path)) {
        if (++count > 256) { matches = 2; break; }
        if (uid == authority->uid && session_valid(authority, path)) {
            if (++matches == 1) authority->session = g_strdup(path);
            else break;
        }
    }
    g_variant_unref(sessions);
    g_variant_unref(result);
    return matches == 1;
}

static gboolean parse_uid(const gchar *text, uid_t *uid)
{
    if (!text || !*text || *text == '0' || strlen(text) > 10) return FALSE;
    guint64 value = 0;
    for (const gchar *p = text; *p; p++) {
        if (!g_ascii_isdigit(*p)) return FALSE;
        value = value * 10 + (guint)(*p - '0');
        if (value >= G_MAXUINT32) return FALSE;
    }
    *uid = (uid_t)value;
    return TRUE;
}

static gboolean parent_uid(pid_t pid, uid_t expected)
{
    gchar path[64], line[512];
    (void)snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    FILE *file = fopen(path, "re");
    if (!file) return FALSE;
    gboolean valid = FALSE;
    while (fgets(line, sizeof(line), file)) {
        unsigned long real, effective, saved, filesystem;
        if (sscanf(line, "Uid:\t%lu\t%lu\t%lu\t%lu", &real, &effective, &saved, &filesystem) == 4) {
            valid = real == expected && effective == expected && saved == expected && filesystem == expected;
            break;
        }
    }
    (void)fclose(file);
    return valid;
}

static gboolean authority_init(Authority *authority)
{
    if (getuid() != 0 || geteuid() != 0 || !parse_uid(g_getenv("PKEXEC_UID"), &authority->uid)) return FALSE;
    if (stat("/proc/self/exe", &authority->executable) != 0 || !deployment_valid(authority)) return FALSE;
    authority->parent = getppid();
    if (authority->parent <= 1) return FALSE;
    authority->parent_fd = (int)syscall(SYS_pidfd_open, authority->parent, 0);
    if (authority->parent_fd < 0 || !parent_alive(authority) ||
        !parent_uid(authority->parent, authority->uid) ||
        getppid() != authority->parent || !parent_alive(authority)) return FALSE;
    /* Do not inherit a caller-selected bus address, modules, locale or helper
     * environment. pkexec already sanitizes, but this boundary is independent. */
    if (clearenv() != 0 || setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) != 0 ||
        setenv("LC_ALL", "C.UTF-8", 1) != 0 || chdir("/") != 0) return FALSE;
    authority->bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    return authority->bus && session_bind(authority) && authority_valid(authority);
}

static gboolean start_child(Broker *broker, GStrv argv)
{
    int input[2] = {-1, -1}, output[2] = {-1, -1}, error[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    gboolean initialized = FALSE, ok = FALSE;
    gchar *uid = g_strdup_printf("PKEXEC_UID=%lu", (unsigned long)broker->authority.uid);
    gchar *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C.UTF-8", uid, NULL};
    if (g_strcmp0(argv[1], HELPER_PATH) != 0 || pipe2(input, O_CLOEXEC) != 0 ||
        pipe2(output, O_CLOEXEC) != 0 || pipe2(error, O_CLOEXEC) != 0) goto cleanup;
    if (posix_spawn_file_actions_init(&actions) != 0) goto cleanup;
    initialized = TRUE;
    if (posix_spawn_file_actions_adddup2(&actions, input[0], STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&actions, error[1], STDERR_FILENO) != 0) goto cleanup;
    int all[] = {input[0], input[1], output[0], output[1], error[0], error[1]};
    for (gsize i = 0; i < G_N_ELEMENTS(all); i++)
        if (posix_spawn_file_actions_addclose(&actions, all[i]) != 0) goto cleanup;
    if (!nonblocking(input[1]) || !nonblocking(output[0]) || !nonblocking(error[0])) goto cleanup;
    if (posix_spawn(&broker->child, HELPER_PATH, &actions, NULL, argv + 1, environment) != 0) {
        broker->child = 0;
        goto cleanup;
    }
    broker->child_input = input[1]; input[1] = -1;
    broker->child_output = output[0]; output[0] = -1;
    broker->child_error = error[0]; error[0] = -1;
    broker->started = g_get_monotonic_time();
    broker->prompt = broker->last_prompt = 0;
    broker->done_seen = broker->done_success = broker->child_exited = FALSE;
    broker->child_status = 1;
    g_string_truncate(broker->child_line, 0);
    ok = TRUE;
cleanup:
    if (initialized) (void)posix_spawn_file_actions_destroy(&actions);
    for (gsize i = 0; i < 2; i++) {
        close_fd(&input[i]); close_fd(&output[i]); close_fd(&error[i]);
    }
    g_free(uid);
    return ok;
}

typedef enum { MESSAGE_INVALID, MESSAGE_REQUEST, MESSAGE_ANSWER, MESSAGE_CLOSE } MessageType;
typedef struct {
    MessageType type;
    guint64 request, prompt;
    gboolean allow;
    GStrv argv;
} Message;

static void message_clear(Message *message)
{
    g_strfreev(message->argv);
    *message = (Message){0};
}

static gboolean parse_message(const gchar *line, gsize length, Message *message)
{
    JsonObject *object = parse_record(line, length);
    if (!object) return FALSE;
    gboolean valid = FALSE;
    if (!json_member(object, "type", G_TYPE_STRING)) goto out;
    const gchar *type = json_object_get_string_member(object, "type");
    guint members = json_object_get_size(object);
    if (g_str_equal(type, "close") && members == 1) {
        message->type = MESSAGE_CLOSE;
        valid = TRUE;
    } else if (g_str_equal(type, "request") && members == 3 && json_member(object, "id", G_TYPE_INT64)) {
        gint64 id = json_object_get_int_member(object, "id");
        JsonNode *node = json_object_get_member(object, "args");
        if (id <= 0 || id > G_MAXINT32 || !node || !JSON_NODE_HOLDS_ARRAY(node)) goto out;
        JsonArray *array = json_node_get_array(node);
        guint count = json_array_get_length(array);
        if (count == 0 || count > 8) goto out;
        const gchar *args[8];
        for (guint i = 0; i < count; i++) {
            JsonNode *argument = json_array_get_element(array, i);
            if (!JSON_NODE_HOLDS_VALUE(argument) || json_node_get_value_type(argument) != G_TYPE_STRING) goto out;
            args[i] = json_node_get_string(argument);
        }
        message->argv = octoshield_action_argv(TRUE, count, args, NULL);
        if (!message->argv) goto out;
        message->request = (guint64)id;
        message->type = MESSAGE_REQUEST;
        valid = TRUE;
    } else if (g_str_equal(type, "answer") && members == 4 &&
               json_member(object, "request", G_TYPE_INT64) &&
               json_member(object, "id", G_TYPE_INT64) && json_member(object, "allow", G_TYPE_BOOLEAN)) {
        gint64 request = json_object_get_int_member(object, "request");
        gint64 prompt = json_object_get_int_member(object, "id");
        if (request <= 0 || request > G_MAXINT32 || prompt <= 0 || prompt > G_MAXINT32) goto out;
        message->type = MESSAGE_ANSWER;
        message->request = (guint64)request;
        message->prompt = (guint64)prompt;
        message->allow = json_object_get_boolean_member(object, "allow");
        valid = TRUE;
    }
out:
    json_object_unref(object);
    if (!valid) message_clear(message);
    return valid;
}

static gboolean message_permitted(const Broker *broker, const Message *message)
{
    if (broker->revoked) return FALSE;
    if (message->type == MESSAGE_CLOSE) return TRUE;
    if (message->type == MESSAGE_REQUEST)
        return broker->child == 0 && message->request == broker->next_request &&
               broker->next_request <= G_MAXINT32;
    if (message->type == MESSAGE_ANSWER)
        return broker->child > 0 && !broker->child_exited && broker->child_input >= 0 &&
               broker->prompt > 0 && message->request == broker->request &&
               message->prompt == broker->prompt;
    return FALSE;
}

/* Called only after request correlation AND a fresh authority check. Clearing
 * the pending ID before the write makes a replay impossible even on EPIPE. */
static void deliver_answer(Broker *broker, const Message *message)
{
    gchar answer[48];
    int length = snprintf(answer, sizeof(answer), "%" G_GUINT64_FORMAT " %s\n",
                          message->prompt, message->allow ? "yes" : "no");
    broker->prompt = 0;
    ssize_t sent;
    do { sent = write(broker->child_input, answer, (gsize)length); } while (sent < 0 && errno == EINTR);
    if (sent != length) broker_revoke(broker, "The helper could not receive the decision.");
}

static void receive_message(Broker *broker, const gchar *line, gsize length)
{
    Message message = {0};
    if (!parse_message(line, length, &message) || !message_permitted(broker, &message)) {
        message_clear(&message);
        broker_revoke(broker, "Invalid or out-of-order session request.");
        return;
    }
    if (message.type == MESSAGE_CLOSE) {
        broker_revoke(broker, "The application closed its administrative session.");
    } else if (!authority_valid(&broker->authority)) {
        broker_revoke(broker, "The active, unlocked local session is no longer available.");
    } else if (message.type == MESSAGE_REQUEST) {
        broker->request = message.request;
        broker->next_request++;
        if (!start_child(broker, message.argv)) broker_revoke(broker, "The fixed privileged helper could not start.");
    } else {
        deliver_answer(broker, &message);
    }
    message_clear(&message);
}

static gboolean forward_event(Broker *broker, const gchar *line, gsize length)
{
    if (broker->revoked) return TRUE;
    OctoshieldEvent event = {0};
    if (broker->done_seen || !octoshield_event_parse(line, (gssize)length, &event, NULL)) return FALSE;
    const gchar *type = event.type == OCTOSHIELD_EVENT_LOG ? "log" :
                        event.type == OCTOSHIELD_EVENT_CONFIRM ? "confirm" : "done";
    JsonObject *object = event_object(type, broker->request);
    gboolean valid = TRUE;
    if (event.type == OCTOSHIELD_EVENT_CONFIRM) {
        valid = broker->prompt == 0 && event.id > broker->last_prompt;
        if (valid) {
            broker->prompt = broker->last_prompt = event.id;
            json_object_set_int_member(object, "id", (gint64)event.id);
        }
    }
    if (event.type == OCTOSHIELD_EVENT_DONE) {
        valid = broker->prompt == 0;
        broker->done_seen = TRUE;
        broker->done_success = event.success;
        json_object_set_boolean_member(object, "success", event.success);
    } else json_object_set_string_member(object, "text", event.text);
    if (valid) valid = queue_event(broker, object);
    json_object_unref(object);
    octoshield_event_clear(&event);
    return valid;
}

static gboolean consume_lines(Broker *broker, GString *buffer, const gchar *data, gsize length, gboolean from_gui)
{
    for (gsize i = 0; i < length; i++) {
        if (broker->revoked) return TRUE;
        if (data[i] == '\n') {
            if (from_gui) receive_message(broker, buffer->str, buffer->len);
            else if (!forward_event(broker, buffer->str, buffer->len)) return FALSE;
            g_string_truncate(buffer, 0);
        } else {
            if (buffer->len >= RECORD_LIMIT || data[i] == '\0' || data[i] == '\r') return FALSE;
            g_string_append_c(buffer, data[i]);
        }
    }
    return TRUE;
}

static void read_input(Broker *broker)
{
    gchar data[4096];
    ssize_t size = read(broker->input, data, sizeof(data));
    if (size > 0) {
        if (!consume_lines(broker, broker->input_line, data, (gsize)size, TRUE))
            broker_revoke(broker, "The application sent an invalid or oversized record.");
    } else if (size == 0 || (errno != EAGAIN && errno != EINTR)) {
        broker_revoke(broker, "The application disconnected.");
    }
}

static void read_child(Broker *broker, gboolean is_error)
{
    int *fd = is_error ? &broker->child_error : &broker->child_output;
    gchar data[4096];
    ssize_t size = read(*fd, data, sizeof(data));
    if (size > 0 && !broker->revoked) {
        if (is_error) {
            JsonObject *event = event_object("log", broker->request);
            gchar *safe = octoshield_text_sanitize(data, size);
            json_object_set_string_member(event, "text", safe);
            if (!queue_event(broker, event)) broker_revoke(broker, "The application is not reading operation output.");
            g_free(safe);
            json_object_unref(event);
        } else if (!consume_lines(broker, broker->child_line, data, (gsize)size, FALSE))
            broker_revoke(broker, "The helper returned an invalid or oversized record.");
    } else if (size == 0 || (size < 0 && errno != EAGAIN && errno != EINTR)) {
        close_fd(fd);
        if (!is_error && broker->child_line->len && !broker->revoked)
            broker_revoke(broker, "The helper disconnected within a record.");
    }
}

static void flush_output(Broker *broker)
{
    if (!broker->output_alive || broker->pending->len == 0) return;
    ssize_t size = write(broker->output, broker->pending->str, broker->pending->len);
    if (size > 0) g_string_erase(broker->pending, 0, size);
    else if (size == 0 || (errno != EINTR && errno != EAGAIN)) {
        broker->output_alive = FALSE;
        broker_revoke(broker, "The application disconnected.");
        g_string_truncate(broker->pending, 0);
    }
}

static gboolean finish_child(Broker *broker)
{
    if (broker->child <= 0) return FALSE;
    if (!broker->child_exited) {
        int status;
        pid_t result = waitpid(broker->child, &status, WNOHANG);
        if (result == broker->child || (result < 0 && errno == ECHILD)) {
            broker->child_exited = TRUE;
            broker->child_status = result == broker->child && WIFEXITED(status) ?
                                   WEXITSTATUS(status) : 1;
            close_fd(&broker->child_input);
        }
    }
    if (!broker->child_exited || broker->child_output >= 0 || broker->child_error >= 0) return FALSE;
    if (!broker->revoked) {
        JsonObject *event = event_object("finished", broker->request);
        json_object_set_int_member(event, "exit_code", broker->done_seen && broker->done_success ? broker->child_status : 1);
        if (!queue_event(broker, event)) broker_revoke(broker, "The application is not reading operation output.");
        json_object_unref(event);
    }
    broker->child = 0;
    broker->prompt = 0;
    return TRUE;
}

static void broker_init(Broker *broker)
{
    *broker = (Broker){.authority = {.parent_fd = -1}, .input = STDIN_FILENO,
        .output = STDOUT_FILENO, .child_input = -1, .child_output = -1,
        .child_error = -1, .next_request = 1, .output_alive = TRUE};
    broker->input_line = g_string_new(NULL);
    broker->child_line = g_string_new(NULL);
    broker->pending = g_string_new(NULL);
}

static void broker_clear(Broker *broker)
{
    close_fd(&broker->child_input);
    close_fd(&broker->child_output);
    close_fd(&broker->child_error);
    close_fd(&broker->authority.parent_fd);
    g_clear_object(&broker->authority.bus);
    g_free(broker->authority.session);
    g_string_free(broker->input_line, TRUE);
    g_string_free(broker->child_line, TRUE);
    g_string_free(broker->pending, TRUE);
}

static int broker_run(Broker *broker)
{
    JsonObject *ready = event_object("ready", 0);
    (void)queue_event(broker, ready);
    json_object_unref(ready);
    gint64 next_check = 0;
    for (;;) {
        gint64 now = g_get_monotonic_time();
        if (!broker->revoked && now >= next_check) {
            if (!authority_valid(&broker->authority))
                broker_revoke(broker, "The local session was locked, switched, or ended.");
            next_check = now + G_USEC_PER_SEC;
        }
        if (!broker->revoked && broker->child > 0 && now - broker->started > OPERATION_LIMIT)
            broker_revoke(broker, "The operation exceeded the administrative session time limit.");
        (void)finish_child(broker);
        if (broker->revoked && broker->child == 0) {
            flush_output(broker);
            return 0;
        }
        if (broker->revoked && now - broker->revoked_at > DRAIN_LIMIT) {
            /* Only signal the fixed helper shell, never its process group.
             * Bash defers its TERM trap while a foreground package manager is
             * completing, so apt/dpkg are not killed mid-transaction. The
             * helper can finish that approved work but cannot read approvals. */
            if (broker->child > 0 && !broker->child_exited) (void)kill(broker->child, SIGTERM);
            return 1;
        }
        struct pollfd fds[] = {
            {.fd = broker->revoked ? -1 : broker->input, .events = POLLIN},
            {.fd = broker->output_alive && broker->pending->len ? broker->output : -1, .events = POLLOUT},
            {.fd = broker->child_output, .events = POLLIN},
            {.fd = broker->child_error, .events = POLLIN},
            {.fd = broker->revoked ? -1 : broker->authority.parent_fd, .events = POLLIN}
        };
        int result = poll(fds, G_N_ELEMENTS(fds), 250);
        if (result < 0) {
            if (errno == EINTR) continue;
            broker_revoke(broker, "The session transport failed.");
            continue;
        }
        /* Revocation always wins over an approval that became readable in
         * the same poll cycle. Every request also repeats the logind check. */
        if (fds[4].revents) broker_revoke(broker, "The application process ended.");
        if (fds[0].revents && !broker->revoked) read_input(broker);
        if (fds[2].revents) read_child(broker, FALSE);
        if (fds[3].revents) read_child(broker, TRUE);
        if (fds[1].revents) flush_output(broker);
    }
}

#ifndef OCTOSHIELD_SESSION_TEST
int main(int argc, char **argv)
{
    (void)argv;
    struct stat input, output;
    if (argc != 1 || fstat(STDIN_FILENO, &input) != 0 || fstat(STDOUT_FILENO, &output) != 0 ||
        !S_ISFIFO(input.st_mode) || !S_ISFIFO(output.st_mode) ||
        !nonblocking(STDIN_FILENO) || !nonblocking(STDOUT_FILENO)) return 1;
    /* No ambient inherited descriptor can become a second command channel. */
    if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0) return 1;
    (void)signal(SIGPIPE, SIG_IGN);
    (void)umask(077);
    Broker broker;
    broker_init(&broker);
    if (!authority_init(&broker.authority)) {
        broker_revoke(&broker, "An active, unlocked local administrator session is required.");
        flush_output(&broker);
        broker_clear(&broker);
        return 1;
    }
    int result = broker_run(&broker);
    broker_clear(&broker);
    return result;
}
#endif
