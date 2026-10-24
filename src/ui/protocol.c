/* SPDX-License-Identifier: Apache-2.0 */
#include "protocol.h"

#include <errno.h>
#include <gio/gio.h>
#include <json-glib/json-glib.h>
#include <string.h>

G_DEFINE_QUARK(octoshield-protocol-error-quark, octoshield_protocol_error)

static gboolean invalid_event(GError **error, const gchar *message)
{
    g_set_error_literal(error, OCTOSHIELD_PROTOCOL_ERROR,
                        OCTOSHIELD_PROTOCOL_ERROR_INVALID_EVENT, message);
    return FALSE;
}

static gboolean member_type(JsonObject *object, const gchar *name, GType type)
{
    JsonNode *node = json_object_get_member(object, name);
    return node != NULL && JSON_NODE_HOLDS_VALUE(node) &&
           json_node_get_value_type(node) == type;
}

gchar *octoshield_text_sanitize(const gchar *text, gssize length)
{
    if (text == NULL || length < -1) {
        return g_strdup("");
    }
    gchar *valid = g_utf8_make_valid(text, length);
    GString *clean = g_string_sized_new(strlen(valid));
    for (const gchar *next = valid; *next != '\0'; next = g_utf8_next_char(next)) {
        gunichar character = g_utf8_get_char(next);
        /* Preserve policy/recovery layout, but remove other controls and
         * invisible formatting that could disguise an approval prompt. */
        if ((g_unichar_iscntrl(character) && character != '\n' && character != '\t') ||
            g_unichar_type(character) == G_UNICODE_FORMAT ||
            character == 0x2028 || character == 0x2029) {
            g_string_append_c(clean, ' ');
        } else {
            g_string_append_unichar(clean, character);
        }
    }
    g_free(valid);
    return g_string_free(clean, FALSE);
}

static gboolean valid_record_bytes(const gchar *line, gsize length)
{
    gboolean escaped = FALSE;
    gboolean in_string = FALSE;
    guint depth = 0;
    for (gsize index = 0; index < length; index++) {
        if (line[index] == '\0' || line[index] == '\n' || line[index] == '\r') {
            return FALSE;
        }
        /* JSON-GLib exposes strings as NUL-terminated values. Reject escaped
         * NUL rather than silently hiding the rest of a security prompt. */
        if (in_string) {
            if (escaped) {
                if (length - index >= 5 &&
                    memcmp(line + index, "u0000", 5) == 0) {
                    return FALSE;
                }
                escaped = FALSE;
            } else if (line[index] == '\\') {
                escaped = TRUE;
            } else if (line[index] == '"') {
                in_string = FALSE;
            } else if ((guchar)line[index] < 0x20) {
                return FALSE;
            }
        } else if (line[index] == '"') {
            in_string = TRUE;
        } else if (line[index] == '{' || line[index] == '[') {
            /* Required values are scalar; a small allowance for extension
             * fields prevents deeply nested input exhausting parser stack. */
            if (++depth > 16) {
                return FALSE;
            }
        } else if (line[index] == '}' || line[index] == ']') {
            if (depth == 0) {
                return FALSE;
            }
            depth--;
        } else if (line[index] == '/' || line[index] == '\'' ||
                   line[index] == '=' || line[index] == ';') {
            /* JSON-GLib can accept JavaScript extensions. This transport is
             * JSON only: no comments, single quotes or assignments. */
            return FALSE;
        } else if (line[index] == '-' || g_ascii_isdigit(line[index])) {
            gsize end = index + 1;
            while (end < length && strchr("-+0123456789.eE", line[end]) != NULL) {
                end++;
            }
            gchar *number = g_strndup(line + index, end - index);
            gchar *tail = NULL;
            errno = 0;
            if (strpbrk(number, ".eE") != NULL) {
                (void)g_ascii_strtod(number, &tail);
            } else {
                (void)g_ascii_strtoll(number, &tail, 10);
            }
            /* JSON-GLib may wrap oversized negative integers into a small
             * positive value. Validate the lexical range before parsing IDs. */
            gboolean valid = errno == 0 && tail != number && *tail == '\0';
            g_free(number);
            if (!valid) {
                return FALSE;
            }
            index = end - 1;
        }
    }
    return !in_string && depth == 0 && g_utf8_validate(line, (gssize)length, NULL);
}

gboolean octoshield_event_parse(const gchar *line, gssize length,
                               OctoshieldEvent *event, GError **error)
{
    gsize size;
    if (line == NULL || event == NULL || length < -1) {
        return invalid_event(error, "Missing or invalid event input.");
    }
    if (length == -1) {
        for (size = 0; size <= OCTOSHIELD_EVENT_MAX_BYTES && line[size]; size++) {
            /* Bounded strlen: reject oversized records before parsing. */
        }
    } else {
        size = (gsize)length;
    }
    if (size > OCTOSHIELD_EVENT_MAX_BYTES) {
        g_set_error_literal(error, OCTOSHIELD_PROTOCOL_ERROR,
                            OCTOSHIELD_PROTOCOL_ERROR_TOO_LARGE,
                            "The helper event exceeds the 64 KiB limit.");
        return FALSE;
    }
    if (size > 0 && line[size - 1] == '\n') {
        size--;
        if (size > 0 && line[size - 1] == '\r') {
            size--;
        }
    }
    if (size == 0 || !valid_record_bytes(line, size)) {
        return invalid_event(error, "The helper event is not one UTF-8 JSON line.");
    }

    JsonParser *parser = json_parser_new();
    GError *parse_error = NULL;
    if (!json_parser_load_from_data(parser, line, (gssize)size, &parse_error)) {
        g_clear_error(&parse_error);
        g_object_unref(parser);
        return invalid_event(error, "The helper returned invalid JSON.");
    }
    JsonNode *root = json_parser_get_root(parser);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        g_object_unref(parser);
        return invalid_event(error, "A helper event must be a JSON object.");
    }
    JsonObject *object = json_node_get_object(root);
    if (!member_type(object, "type", G_TYPE_STRING)) {
        g_object_unref(parser);
        return invalid_event(error, "A helper event needs a string type.");
    }

    const gchar *type = json_object_get_string_member(object, "type");
    OctoshieldEvent parsed = {0};
    if (g_str_equal(type, "log") || g_str_equal(type, "confirm") || g_str_equal(type, "data")) {
        if (!member_type(object, "text", G_TYPE_STRING)) {
            g_object_unref(parser);
            return invalid_event(error, "A log or confirmation needs string text.");
        }
        parsed.type = g_str_equal(type, "data") ? OCTOSHIELD_EVENT_DATA :
                      g_str_equal(type, "log") ? OCTOSHIELD_EVENT_LOG : OCTOSHIELD_EVENT_CONFIRM;
        if (parsed.type == OCTOSHIELD_EVENT_CONFIRM) {
            if (!member_type(object, "id", G_TYPE_INT64)) {
                g_object_unref(parser);
                return invalid_event(error, "A confirmation needs an integer id.");
            }
            gint64 id = json_object_get_int_member(object, "id");
            if (id <= 0 || id > (gint64)OCTOSHIELD_CONFIRM_MAX_ID) {
                g_object_unref(parser);
                return invalid_event(error, "The confirmation id is out of range.");
            }
            parsed.id = (guint64)id;
        }
        /* Structured text is JSON, not display text. Sanitize extracted labels
         * when rendering; rewriting its bytes can invalidate identifiers. */
        parsed.text = parsed.type == OCTOSHIELD_EVENT_DATA ?
            g_strdup(json_object_get_string_member(object, "text")) :
            octoshield_text_sanitize(json_object_get_string_member(object, "text"), -1);
    } else if (g_str_equal(type, "done")) {
        if (!member_type(object, "success", G_TYPE_BOOLEAN)) {
            g_object_unref(parser);
            return invalid_event(error, "A completion event needs boolean success.");
        }
        parsed.type = OCTOSHIELD_EVENT_DONE;
        parsed.success = json_object_get_boolean_member(object, "success");
        if (json_object_has_member(object, "change_started")) {
            if (!member_type(object, "change_started", G_TYPE_BOOLEAN)) {
                g_object_unref(parser);
                return invalid_event(error, "A completion change_started field must be boolean.");
            }
            parsed.change_started_known = TRUE;
            parsed.change_started = json_object_get_boolean_member(object, "change_started");
        }
    } else {
        g_object_unref(parser);
        return invalid_event(error, "The helper event type is unsupported.");
    }
    g_object_unref(parser);
    *event = parsed;
    return TRUE;
}

void octoshield_event_clear(OctoshieldEvent *event)
{
    if (event != NULL) {
        g_clear_pointer(&event->text, g_free);
        *event = (OctoshieldEvent){0};
    }
}

static gboolean one_of(const gchar *value, const gchar *const *choices)
{
    for (gsize index = 0; choices[index] != NULL; index++) {
        if (g_str_equal(value, choices[index])) {
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean decimal(const gchar *value, guint64 maximum)
{
    guint64 result = 0;
    if (*value < '1' || *value > '9') {
        return FALSE;
    }
    for (const gchar *next = value; *next != '\0'; next++) {
        if (*next < '0' || *next > '9') {
            return FALSE;
        }
        guint digit = (guint)(*next - '0');
        if (result > (maximum - digit) / 10) {
            return FALSE;
        }
        result = result * 10 + digit;
    }
    return result <= maximum;
}

static gboolean ipv4_subnet(const gchar *value)
{
    gchar **parts = g_strsplit(value, "/", -1);
    gboolean valid = g_strv_length(parts) == 2 && decimal(parts[1], 32);
    GInetAddress *address = valid ? g_inet_address_new_from_string(parts[0]) : NULL;
    if (address == NULL || g_inet_address_get_family(address) != G_SOCKET_FAMILY_IPV4) {
        valid = FALSE;
    } else {
        gchar *canonical = g_inet_address_to_string(address);
        valid = g_str_equal(parts[0], canonical);
        g_free(canonical);
    }
    g_clear_object(&address);
    g_strfreev(parts);
    return valid;
}

static gboolean backup_id(const gchar *value)
{
    gsize length = strlen(value);
    if (length < 18 || length > 40 || value[8] != 'T' ||
        value[15] != 'Z' || value[16] != '-') {
        return FALSE;
    }
    for (gsize index = 0; index < 15; index++) {
        if (index != 8 && !g_ascii_isdigit(value[index])) {
            return FALSE;
        }
    }
    if (value[17] < '1' || value[17] > '9') {
        return FALSE;
    }
    for (gsize index = 18; index < length; index++) {
        if (!g_ascii_isdigit(value[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean profile_id(const gchar *value)
{
    gsize length = strlen(value);
    if (length == 0 || length > 32 || !g_ascii_islower(value[0]) || g_str_equal(value, "unmanaged"))
        return FALSE;
    for (gsize i = 1; i < length; i++)
        if (!g_ascii_islower(value[i]) && !g_ascii_isdigit(value[i]) && value[i] != '-')
            return FALSE;
    return TRUE;
}

static gboolean profile_action(gsize argc, const gchar *const *args)
{
    static const gchar *const controls[] = {"firewall", "usb", "network", "services", "monitor", NULL};
    static const gchar *const keys[] = {"network.autoconnect", "network.discovery", "services.printing", "services.bluetooth", "services.ssh", "services.discovery", "services.samba", "services.remote_desktop", "monitor.enabled", NULL};
    if (argc == 2)
        return g_str_equal(args[1], "list") || g_str_equal(args[1], "restore");
    if (argc == 3 && g_str_equal(args[1], "restore"))
        return one_of(args[2], controls);
    if (argc < 3 || !profile_id(args[2]))
        return FALSE;
    if (g_str_equal(args[1], "show") || g_str_equal(args[1], "delete"))
        return argc == 3;
    if (g_str_equal(args[1], "create"))
        return argc == 4 && profile_id(args[3]);
    if (g_str_equal(args[1], "apply"))
        return argc == 3 || (argc == 4 && one_of(args[3], controls));
    if (g_str_equal(args[1], "set"))
        return argc == 5 && one_of(args[3], keys) &&
               (g_str_has_prefix(args[3], "services.") ?
                (g_str_equal(args[4], "enabled") || g_str_equal(args[4], "disabled") || g_str_equal(args[4], "baseline")) :
                (g_str_equal(args[4], "true") || g_str_equal(args[4], "false")));
    if (g_str_equal(args[1], "rule-remove"))
        return argc == 4 && g_regex_match_simple("^r[0-9]{1,16}-[0-9]{1,10}-[0-9]{1,5}$", args[3], 0, 0);
    if (g_str_equal(args[1], "rule-add")) {
        if (argc != 8 || !decimal(args[3], 65535) ||
            !(g_str_equal(args[4], "tcp") || g_str_equal(args[4], "udp")))
            return FALSE;
        g_autoptr(GInetAddressMask) source = g_inet_address_mask_new_from_string(args[5], NULL);
        if (source == NULL && !g_str_equal(args[5], "any"))
            return FALSE;
        if (!g_str_equal(args[6], "any")) {
            if (strlen(args[6]) == 0 || strlen(args[6]) > 15 || !g_ascii_isalnum(args[6][0]))
                return FALSE;
            for (const char *p = args[6]; *p; p++)
                if (!g_ascii_isalnum(*p) && *p != '_' && *p != '-' && *p != '.' && *p != ':')
                    return FALSE;
        }
        return g_str_equal(args[7], "0") || decimal(args[7], 10080);
    }
    return FALSE;
}

static gboolean access_action(gsize argc, const gchar *const *args)
{
    if (g_str_equal(args[1], "list"))
        return argc == 2 || (argc == 3 && profile_id(args[2]));
    if (argc < 3 || !profile_id(args[2])) return FALSE;
    gboolean update = g_str_equal(args[1], "update");
    if (g_str_equal(args[1], "revoke") || update) {
        if (argc < 4 || !g_regex_match_simple("^[gr][0-9]{1,16}-[0-9]{1,10}-[0-9]{1,5}$", args[3], 0, 0))
            return FALSE;
        if (!update) return argc == 4;
    } else if (!g_str_equal(args[1], "allow")) return FALSE;
    guint offset = update ? 4 : 3;
    if (argc != offset + 5 || strlen(args[offset]) > 191) return FALSE;
    g_auto(GStrv) ports = g_strsplit(args[offset], ",", -1);
    if (g_strv_length(ports) > 32) return FALSE;
    for (guint i = 0; ports[i] != NULL; i++) {
        if (!decimal(ports[i], 65535)) return FALSE;
        for (guint j = 0; j < i; j++)
            if (g_str_equal(ports[i], ports[j])) return FALSE;
        /* Reuse the same strict protocol/address/interface/duration checks. */
        const gchar *rule[] = {"profile", "rule-add", args[2], ports[i], args[offset + 1], args[offset + 2], args[offset + 3], args[offset + 4]};
        if (!profile_action(8, rule)) return FALSE;
    }
    return TRUE;
}

static gboolean connections_action(gsize argc, const gchar *const *args)
{
    if (argc == 2 && (g_str_equal(args[1], "list") || g_str_equal(args[1], "reconcile"))) return TRUE;
    if (argc < 3 || !g_uuid_string_is_valid(args[2])) return FALSE;
    if (g_str_equal(args[1], "reconnect")) return argc == 3;
    if (argc != 5 || !g_str_equal(args[1], "set")) return FALSE;
    if (g_str_equal(args[3], "mac"))
        return g_str_equal(args[4], "stable") || g_str_equal(args[4], "permanent");
    return (g_str_equal(args[3], "autoconnect") || g_str_equal(args[3], "discovery")) &&
           (g_str_equal(args[4], "true") || g_str_equal(args[4], "false"));
}

static gboolean privileged_action(gsize argc, const gchar *const *args)
{
    static const gchar *const controls[] = {
        "firewall", "network", "services", "sudo", "updates", "apparmor",
        "usb", "monitor", NULL
    };
    static const gchar *const services[] = {
        "ssh.service", "avahi-daemon.service", "bluetooth.service",
        "cups.service", NULL
    };
    static const gchar *const monitor[] = {"status", "logs", "disable", NULL};

    if (argc == 1) {
        return g_str_equal(args[0], "status") || g_str_equal(args[0], "inspect") ||
               g_str_equal(args[0], "backups");
    }
    if (g_str_equal(args[0], "apply")) {
        return argc == 2 && one_of(args[1], controls);
    }
    if (g_str_equal(args[0], "profile"))
        return profile_action(argc, args);
    if (g_str_equal(args[0], "access")) return access_action(argc, args);
    if (g_str_equal(args[0], "connections")) return connections_action(argc, args);
    if (g_str_equal(args[0], "diagnostics")) {
        static const gchar *const topics[] = {"disk_encryption", "containers", "forwarding", "network", NULL};
        return argc == 3 && g_str_equal(args[1], "show") && one_of(args[2], topics);
    }
    if (g_str_equal(args[0], "backup-show")) {
        return argc == 2 && backup_id(args[1]);
    }
    if (g_str_equal(args[0], "monitor")) {
        return argc == 2 && one_of(args[1], monitor);
    }
    if (g_str_equal(args[0], "usb")) {
        if (argc == 3 && g_str_equal(args[1], "enroll"))
            return profile_id(args[2]);
        if (argc == 2) {
            return g_str_equal(args[1], "list") || g_str_equal(args[1], "devices");
        }
        if (argc < 3 || !decimal(args[2], G_GUINT64_CONSTANT(4294967294))) {
            return FALSE;
        }
        if (g_str_equal(args[1], "approve") || g_str_equal(args[1], "revoke")) {
            if (argc != 6 || strlen(args[3]) != 64 || !profile_id(args[4]))
                return FALSE;
            for (const gchar *p = args[3]; *p; p++)
                if (!g_ascii_isdigit(*p) && (*p < 'a' || *p > 'f'))
                    return FALSE;
            if (g_str_equal(args[1], "approve"))
                return g_str_equal(args[5], "once") || g_str_equal(args[5], "profile");
            return g_str_equal(args[5], "block") || g_str_equal(args[5], "forget");
        }
        if (g_str_equal(args[1], "block") || g_str_equal(args[1], "forget")) {
            return argc == 3;
        }
        return g_str_equal(args[1], "allow") &&
               (argc == 3 || (argc == 4 && g_str_equal(args[3], "--permanent")));
    }
    if (g_str_equal(args[0], "office")) {
        if (argc == 4 && g_str_equal(args[1], "firewall")) {
            return decimal(args[2], 65535) && ipv4_subnet(args[3]);
        }
        if (argc == 3 && g_str_equal(args[1], "network")) {
            return g_uuid_string_is_valid(args[2]);
        }
        return argc == 3 && g_str_equal(args[1], "service") &&
               one_of(args[2], services);
    }
    return FALSE;
}

static gboolean user_action(gsize argc, const gchar *const *args)
{
    static const gchar *const desktop[] = {"apply", "restore", "status", NULL};
    static const gchar *const monitor[] = {
        "enable-desktop", "disable-desktop", "status", NULL
    };
    if (argc == 1) {
        return g_str_equal(args[0], "recovery");
    }
    if (argc == 2 && g_str_equal(args[0], "updates") && g_str_equal(args[1], "check"))
        return TRUE;
    if (g_str_equal(args[0], "containers")) {
        if (argc < 3 || !g_regex_match_simple("^[a-f0-9]{64}$", args[2], 0, 0)) return FALSE;
        if (g_str_equal(args[1], "plan")) return argc == 3;
        return argc == 4 && g_str_equal(args[1], "localize") &&
               g_regex_match_simple("^[a-f0-9]{64}$", args[3], 0, 0);
    }
    return argc == 2 &&
           ((g_str_equal(args[0], "desktop") && one_of(args[1], desktop)) ||
            (g_str_equal(args[0], "monitor") && one_of(args[1], monitor)));
}

GStrv octoshield_action_argv(gboolean privileged, gsize argc,
                           const gchar *const *args, GError **error)
{
    gboolean valid = args != NULL && argc >= 1 && argc <= 9;
    for (gsize index = 0; valid && index < argc; index++) {
        valid = args[index] != NULL && strlen(args[index]) <= 256;
    }
    if (valid) {
        valid = privileged ? privileged_action(argc, args) : user_action(argc, args);
    }
    if (!valid) {
        g_set_error_literal(error, OCTOSHIELD_PROTOCOL_ERROR,
                            OCTOSHIELD_PROTOCOL_ERROR_INVALID_ACTION,
                            "This action or its arguments are not permitted.");
        return NULL;
    }
    GStrv argv = g_new0(gchar *, argc + 3);
    argv[0] = g_strdup(privileged ? "/usr/bin/pkexec" : "/usr/bin/octoshield");
    argv[1] = g_strdup(privileged ? "/usr/libexec/octoshield-helper" : "user-api");
    for (gsize index = 0; index < argc; index++) {
        argv[index + 2] = g_strdup(args[index]);
    }
    return argv;
}
