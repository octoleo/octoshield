/* SPDX-License-Identifier: Apache-2.0 */
#include "protocol.h"

#include <string.h>

static void parse_valid(void)
{
    OctoshieldEvent event = {0};
    GError *error = NULL;
    g_assert_true(octoshield_event_parse(
        "{\"type\":\"log\",\"text\":\"Firewall ready\"}\n", -1, &event, &error));
    g_assert_no_error(error);
    g_assert_cmpint(event.type, ==, OCTOSHIELD_EVENT_LOG);
    g_assert_cmpstr(event.text, ==, "Firewall ready");
    g_assert_cmpuint(event.id, ==, 0);
    octoshield_event_clear(&event);

    g_assert_true(octoshield_event_parse(
        "{\"type\":\"confirm\",\"id\":1,\"text\":\"Trust this device?\",\"future\":12}\r\n",
        -1, &event, &error));
    g_assert_no_error(error);
    g_assert_cmpint(event.type, ==, OCTOSHIELD_EVENT_CONFIRM);
    g_assert_cmpstr(event.text, ==, "Trust this device?");
    g_assert_cmpuint(event.id, ==, 1);
    octoshield_event_clear(&event);

    g_assert_true(octoshield_event_parse(
        "{\"type\":\"confirm\",\"id\":2147483647,\"text\":\"Trust this device?\"}",
        -1, &event, &error));
    g_assert_no_error(error);
    g_assert_cmpuint(event.id, ==, OCTOSHIELD_CONFIRM_MAX_ID);
    octoshield_event_clear(&event);

    g_assert_true(octoshield_event_parse(
        "{\"type\":\"done\",\"success\":true}", -1, &event, &error));
    g_assert_no_error(error);
    g_assert_cmpint(event.type, ==, OCTOSHIELD_EVENT_DONE);
    g_assert_true(event.success);
    g_assert_null(event.text);
    g_assert_cmpuint(event.id, ==, 0);
    octoshield_event_clear(&event);

    g_assert_true(octoshield_event_parse(
        "{\"type\":\"done\",\"success\":false}", -1, &event, &error));
    g_assert_no_error(error);
    g_assert_false(event.success);
    octoshield_event_clear(&event);
    octoshield_event_clear(&event);
    octoshield_event_clear(NULL);
}

static void parse_invalid(void)
{
    static const gchar *const invalid[] = {
        "", " ", "null", "true", "[]", "42", "\"log\"", "{}",
        "{\"type\":null}", "{\"type\":false}", "{\"type\":1}",
        "{\"type\":[]}", "{\"type\":{}}", "{\"type\":\"unknown\"}",
        "{\"type\":\"log\"}", "{\"type\":\"log\",\"text\":null}",
        "{\"type\":\"log\",\"text\":12}", "{\"type\":\"log\",\"text\":true}",
        "{\"type\":\"log\",\"text\":[]}", "{\"type\":\"log\",\"text\":{}}",
        "{\"type\":\"confirm\"}", "{\"type\":\"confirm\",\"text\":false}",
        "{\"type\":\"confirm\",\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":0,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":-1,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":1.5,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":1.0,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":1e0,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":\"1\",\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":true,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":null,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":[],\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":{},\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":2147483648,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":4294967296,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":18446744073709551617,\"text\":\"Trust?\"}",
        "{\"type\":\"confirm\",\"id\":-18446744073709551617,\"text\":\"Trust?\"}",
        "{\"type\":\"done\"}", "{\"type\":\"done\",\"success\":\"true\"}",
        "{\"type\":\"done\",\"success\":1}",
        "{\"type\":\"done\",\"success\":null}",
        "{\"type\":\"done\",\"success\":[]}",
        "{\"type\":\"done\",\"success\":{}}",
        "{\"type\":\"done\",\"success\":true",
        "{\"type\":\"log\",\"text\":\"a\"}\n{\"type\":\"done\",\"success\":true}",
        "{\"type\":\"log\",\"text\":\"a\"}\n\n",
        "{\"type\":\"log\",\"text\":\"a\"}\r",
        "{\n\"type\":\"done\",\"success\":true}",
        "{\"type\":\"log\",\"text\":\"before\\u0000after\"}",
        "{\"type\":\"log\",\"text\":\"bad\xff\"}",
        "var event = {\"type\":\"done\",\"success\":true};",
        "{/*comment*/\"type\":\"done\",\"success\":true}",
        "{'type':'done','success':true}",
        "{type:\"done\",success:true}",
        "{\"type\":\"done\",\"success\":true,}", NULL
    };
    for (gsize index = 0; invalid[index] != NULL; index++) {
        OctoshieldEvent event = {0};
        GError *error = NULL;
        g_test_message("Reject record %zu", index);
        g_assert_false(octoshield_event_parse(invalid[index], -1, &event, &error));
        g_assert_error(error, OCTOSHIELD_PROTOCOL_ERROR,
                       OCTOSHIELD_PROTOCOL_ERROR_INVALID_EVENT);
        g_assert_null(event.text);
        g_clear_error(&error);
    }
    OctoshieldEvent event = {0};
    g_assert_false(octoshield_event_parse(NULL, 0, &event, NULL));
    g_assert_false(octoshield_event_parse("{}", -2, &event, NULL));
    g_assert_false(octoshield_event_parse("{}", -1, NULL, NULL));
    const gchar binary[] = "{\"type\":\"done\",\"success\":true}\0hidden";
    g_assert_false(octoshield_event_parse(binary, sizeof(binary) - 1, &event, NULL));

    GString *nested = g_string_new("{\"type\":\"log\",\"text\":\"hello\",\"extra\":");
    for (guint index = 0; index < 32; index++) g_string_append_c(nested, '[');
    g_string_append(nested, "true");
    for (guint index = 0; index < 32; index++) g_string_append_c(nested, ']');
    g_string_append_c(nested, '}');
    g_assert_false(octoshield_event_parse(nested->str, (gssize)nested->len, &event, NULL));
    g_string_free(nested, TRUE);
}

static void parse_sanitize(void)
{
    OctoshieldEvent event = {0};
    GError *error = NULL;
    g_assert_true(octoshield_event_parse(
        "{\"type\":\"log\",\"text\":\"<b>USB</b>\\u001b[31m\\n\\t\\r\\u007f\\u0085\\u202e\\u2028é\\\\u0000\"}",
        -1, &event, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(event.text, ==, "<b>USB</b> [31m\n\t     é\\u0000");
    g_assert_true(g_utf8_validate(event.text, -1, NULL));
    octoshield_event_clear(&event);

    gchar *safe = octoshield_text_sanitize("prefix\xff\x1b\n\tsuffix", -1);
    g_assert_cmpstr(safe, ==, "prefix\xef\xbf\xbd \n\tsuffix");
    g_free(safe);
    safe = octoshield_text_sanitize("visible HIDDEN", 7);
    g_assert_cmpstr(safe, ==, "visible");
    g_free(safe);
    safe = octoshield_text_sanitize(NULL, -1);
    g_assert_cmpstr(safe, ==, "");
    g_free(safe);
    safe = octoshield_text_sanitize("ignored", -2);
    g_assert_cmpstr(safe, ==, "");
    g_free(safe);
}

static void parse_length(void)
{
    const gchar *prefix = "{\"type\":\"log\",\"text\":\"";
    const gchar *suffix = "\"}";
    gsize text_size = OCTOSHIELD_EVENT_MAX_BYTES - strlen(prefix) - strlen(suffix);
    GString *record = g_string_sized_new(OCTOSHIELD_EVENT_MAX_BYTES + 2);
    g_string_append(record, prefix);
    for (gsize index = 0; index < text_size; index++) g_string_append_c(record, 'a');
    g_string_append(record, suffix);
    OctoshieldEvent event = {0};
    GError *error = NULL;
    g_assert_cmpuint(record->len, ==, OCTOSHIELD_EVENT_MAX_BYTES);
    g_assert_true(octoshield_event_parse(record->str, (gssize)record->len, &event, &error));
    g_assert_no_error(error);
    g_assert_cmpuint(strlen(event.text), ==, text_size);
    octoshield_event_clear(&event);
    g_string_append_c(record, ' ');
    g_assert_false(octoshield_event_parse(record->str, -1, &event, &error));
    g_assert_error(error, OCTOSHIELD_PROTOCOL_ERROR, OCTOSHIELD_PROTOCOL_ERROR_TOO_LARGE);
    g_clear_error(&error);
    g_assert_false(octoshield_event_parse(record->str, (gssize)record->len, &event, &error));
    g_assert_error(error, OCTOSHIELD_PROTOCOL_ERROR, OCTOSHIELD_PROTOCOL_ERROR_TOO_LARGE);
    g_clear_error(&error);
    g_string_free(record, TRUE);
}

static void assert_action(gboolean privileged, const gchar *const *args)
{
    gsize argc = g_strv_length((gchar **)args);
    GError *error = NULL;
    GStrv argv = octoshield_action_argv(privileged, argc, args, &error);
    g_assert_no_error(error);
    g_assert_nonnull(argv);
    g_assert_cmpuint(g_strv_length(argv), ==, argc + 2);
    g_assert_cmpstr(argv[0], ==, privileged ? "/usr/bin/pkexec" : "/usr/bin/octoshield");
    g_assert_cmpstr(argv[1], ==, privileged ? "/usr/libexec/octoshield-helper" : "user-api");
    for (gsize index = 0; index < argc; index++) {
        g_assert_cmpstr(argv[index + 2], ==, args[index]);
        g_assert_true(argv[index + 2] != args[index]);
    }
    g_assert_null(argv[argc + 2]);
    g_strfreev(argv);
}

static void action_privileged(void)
{
    static const gchar *const actions[][5] = {
        {"apply", "firewall", NULL}, {"apply", "network", NULL},
        {"apply", "services", NULL}, {"apply", "sudo", NULL},
        {"apply", "updates", NULL}, {"apply", "apparmor", NULL},
        {"apply", "usb", NULL}, {"apply", "monitor", NULL},
        {"usb", "list", NULL}, {"usb", "allow", "1", NULL},
        {"usb", "allow", "4294967294", "--permanent", NULL},
        {"usb", "block", "12345", NULL},
        {"office", "firewall", "1", "192.168.1.0/24", NULL},
        {"office", "firewall", "65535", "255.255.255.255/32", NULL},
        {"office", "firewall", "443", "0.0.0.0/1", NULL},
        {"office", "network", "01234567-89AB-cdef-0123-456789abcdef", NULL},
        {"office", "service", "ssh.service", NULL},
        {"office", "service", "avahi-daemon.service", NULL},
        {"office", "service", "bluetooth.service", NULL},
        {"office", "service", "cups.service", NULL},
        {"status", NULL}, {"backups", NULL},
        {"backup-show", "20261012T114118Z-1", NULL},
        {"backup-show", "20261012T114118Z-12345678901234567890123", NULL},
        {"monitor", "status", NULL}, {"monitor", "logs", NULL},
        {"monitor", "disable", NULL}
    };
    for (gsize index = 0; index < G_N_ELEMENTS(actions); index++) {
        assert_action(TRUE, actions[index]);
    }
}

static void action_user(void)
{
    static const gchar *const actions[][3] = {
        {"desktop", "apply", NULL}, {"desktop", "restore", NULL},
        {"desktop", "status", NULL}, {"monitor", "enable-desktop", NULL},
        {"monitor", "disable-desktop", NULL}, {"monitor", "status", NULL},
        {"recovery", NULL}
    };
    for (gsize index = 0; index < G_N_ELEMENTS(actions); index++) {
        assert_action(FALSE, actions[index]);
    }
}

static void reject_action(gboolean privileged, gsize argc, const gchar *const *args)
{
    GError *error = NULL;
    g_assert_null(octoshield_action_argv(privileged, argc, args, &error));
    g_assert_error(error, OCTOSHIELD_PROTOCOL_ERROR,
                   OCTOSHIELD_PROTOCOL_ERROR_INVALID_ACTION);
    g_clear_error(&error);
}

static void action_reject(void)
{
    static const gchar *const actions[][6] = {
        {"sh", "-c", "id", NULL}, {"/bin/sh", NULL},
        {"apply", NULL}, {"apply", "all", NULL}, {"apply", "firewall;id", NULL},
        {"apply", "firewall", "--force", NULL},
        {"usb", NULL}, {"usb", "allow", NULL}, {"usb", "allow", "0", NULL},
        {"usb", "allow", "01", NULL}, {"usb", "allow", "4294967295", NULL},
        {"usb", "allow", "99999999999999999999999999999999999", NULL},
        {"usb", "allow", "-1", NULL}, {"usb", "allow", "+1", NULL},
        {"usb", "allow", "1;id", NULL}, {"usb", "allow", "$(id)", NULL},
        {"usb", "allow", "1\n2", NULL}, {"usb", "allow", "*", NULL},
        {"usb", "allow", "1", "--all", NULL},
        {"usb", "block", "1", "--permanent", NULL},
        {"usb", "list", "1", NULL}, {"usb", "reject", "1", NULL},
        {"office", "firewall", "0", "192.168.1.0/24", NULL},
        {"office", "firewall", "65536", "192.168.1.0/24", NULL},
        {"office", "firewall", "080", "192.168.1.0/24", NULL},
        {"office", "firewall", "80/tcp", "192.168.1.0/24", NULL},
        {"office", "firewall", "80", "0.0.0.0/0", NULL},
        {"office", "firewall", "80", "192.168.1.0/33", NULL},
        {"office", "firewall", "80", "192.168.1.0/024", NULL},
        {"office", "firewall", "80", "192.168.1.0/-1", NULL},
        {"office", "firewall", "80", "256.168.1.0/24", NULL},
        {"office", "firewall", "80", "192.168.01.0/24", NULL},
        {"office", "firewall", "80", "192.168.1.0/24/1", NULL},
        {"office", "firewall", "80", "192.168.1.0", NULL},
        {"office", "firewall", "80", "::1/32", NULL},
        {"office", "firewall", "80", "127.1/32", NULL},
        {"office", "firewall", "80", "office.example/24", NULL},
        {"office", "firewall", "80", "192.168.1.0/24;id", NULL},
        {"office", "network", "01234567-89ab-cdef-0123-456789abcdeg", NULL},
        {"office", "network", "$(nmcli)", NULL},
        {"office", "service", "sshd.service", NULL},
        {"office", "service", "cups.socket", NULL},
        {"office", "service", "--all", NULL},
        {"office", "service", "ssh.service;id", NULL},
        {"backup-show", "../../etc/shadow", NULL},
        {"backup-show", "20261012T114118Z-0", NULL},
        {"backup-show", "20261012T114118Z-01", NULL},
        {"backup-show", "20261012T114118Z-1.log", NULL},
        {"backup-show", "20261012T114118Z-123456789012345678901234", NULL},
        {"backup-show", "20261012T114118Z-1\n", NULL},
        {"monitor", "enable-desktop", NULL}, {"monitor", "enable", NULL},
        {"status", "extra", NULL}, {"backups", "extra", NULL},
        {"desktop", "apply", NULL}, {"recovery", NULL}
    };
    for (gsize index = 0; index < G_N_ELEMENTS(actions); index++) {
        g_test_message("Reject action %zu", index);
        reject_action(TRUE, g_strv_length((gchar **)actions[index]), actions[index]);
    }
    const gchar *const apply[] = {"apply", "firewall"};
    reject_action(FALSE, 2, apply);
    const gchar *const desktop[] = {"desktop", "apply", "--force"};
    reject_action(FALSE, 3, desktop);
    const gchar *const monitor[] = {"monitor", "disable"};
    reject_action(FALSE, 2, monitor);
    const gchar *const missing[] = {"apply", NULL};
    reject_action(TRUE, 2, missing);
    reject_action(TRUE, 0, apply);
    reject_action(TRUE, G_MAXSIZE, apply);
    reject_action(TRUE, 1, NULL);
    gchar *long_arg = g_strnfill(129, 'a');
    const gchar *const oversized[] = {"apply", long_arg};
    reject_action(TRUE, 2, oversized);
    g_free(long_arg);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ui/protocol/valid", parse_valid);
    g_test_add_func("/ui/protocol/invalid", parse_invalid);
    g_test_add_func("/ui/protocol/sanitize", parse_sanitize);
    g_test_add_func("/ui/protocol/length", parse_length);
    g_test_add_func("/ui/action/privileged", action_privileged);
    g_test_add_func("/ui/action/user", action_user);
    g_test_add_func("/ui/action/reject", action_reject);
    return g_test_run();
}
