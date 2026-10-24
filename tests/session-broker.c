/* SPDX-License-Identifier: Apache-2.0 */
#define OCTOSHIELD_SESSION_TEST
#include "../src/session-broker.c"

static Message message(const gchar *json)
{
    Message parsed = {0};
    g_assert_true(parse_message(json, strlen(json), &parsed));
    return parsed;
}

static void test_requests(void)
{
    Message parsed = message("{\"type\":\"request\",\"id\":1,\"args\":[\"usb\",\"allow\",\"123\",\"--permanent\"]}");
    g_assert_cmpint(parsed.type, ==, MESSAGE_REQUEST);
    g_assert_cmpuint(parsed.request, ==, 1);
    g_assert_cmpstr(parsed.argv[0], ==, "/usr/bin/pkexec");
    g_assert_cmpstr(parsed.argv[1], ==, HELPER_PATH);
    g_assert_cmpstr(parsed.argv[2], ==, "usb");
    g_assert_cmpstr(parsed.argv[5], ==, "--permanent");
    g_assert_null(parsed.argv[6]);
    message_clear(&parsed);
    parsed = message("{\"type\":\"answer\",\"request\":4,\"id\":2,\"allow\":false}");
    g_assert_false(parsed.allow);
    g_assert_cmpuint(parsed.prompt, ==, 2);
    message_clear(&parsed);
    parsed = message("{\"type\":\"close\"}");
    g_assert_cmpint(parsed.type, ==, MESSAGE_CLOSE);
    message_clear(&parsed);
}

static void test_bound_usb_requests(void)
{
    const gchar *fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const struct { const gchar *action; const gchar *mode; gboolean valid; } cases[] = {
        {"approve", "once", TRUE}, {"approve", "profile", TRUE},
        {"revoke", "block", TRUE}, {"revoke", "forget", TRUE},
        {"approve", "block", FALSE}, {"revoke", "profile", FALSE},
        {"approve", "forever", FALSE}, {"revoke", "once", FALSE}
    };
    for (guint i = 0; i < G_N_ELEMENTS(cases); i++) {
        gchar *json = g_strdup_printf("{\"type\":\"request\",\"id\":1,\"args\":[\"usb\",\"%s\",\"123\",\"%s\",\"office\",\"%s\"]}",
                                       cases[i].action, fingerprint, cases[i].mode);
        Message parsed = {0};
        g_assert_cmpint(parse_message(json, strlen(json), &parsed), ==, cases[i].valid);
        if (cases[i].valid) {
            g_assert_cmpstr(parsed.argv[3], ==, cases[i].action);
            g_assert_cmpstr(parsed.argv[5], ==, fingerprint);
            g_assert_cmpstr(parsed.argv[6], ==, "office");
            g_assert_cmpstr(parsed.argv[7], ==, cases[i].mode);
            g_assert_null(parsed.argv[8]);
        }
        message_clear(&parsed); g_free(json);
    }
    gchar *json = g_strdup_printf("{\"type\":\"request\",\"id\":1,\"args\":[\"usb\",\"approve\",\"123\",\"%s\",\"office;id\",\"once\"]}", fingerprint);
    Message parsed = {0};
    g_assert_false(parse_message(json, strlen(json), &parsed));
    g_free(json);
}

static void test_rejections(void)
{
    const gchar *invalid[] = {
        "", "[]", "null", "{}",
        "{\"type\":\"close\",\"type\":\"close\"}",
        "{\"type\":\"close\",\"t\\u0079pe\":\"close\"}",
        "{\"type\":\"close\",}", "{\"type\":\"close\",\"args\":[]}",
        "{\"type\":\"request\",\"id\":0,\"args\":[\"status\"]}",
        "{\"type\":\"request\",\"id\":-1,\"args\":[\"status\"]}",
        "{\"type\":\"request\",\"id\":1.0,\"args\":[\"status\"]}",
        "{\"type\":\"request\",\"id\":1e0,\"args\":[\"status\"]}",
        "{\"type\":\"request\",\"id\":2147483648,\"args\":[\"status\"]}",
        "{\"type\":\"request\",\"id\":-18446744073709551615,\"args\":[\"status\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"sh\",\"-c\",\"id\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"usb\",\"allow\",\"1;id\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"usb\",\"allow\",\"$(id)\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"usb\",\"allow\",\"1\\u0000;id\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"usb\",\"allow\",123]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"status\"],\"path\":\"/tmp/helper\"}",
        "{\"type\":\"answer\",\"request\":1,\"id\":1,\"allow\":\"yes\"}",
        "{\"type\":\"answer\",\"request\":1,\"id\":1,\"allow\":true,\"args\":[]}",
        "{'type':'close'}", "/* comment */{\"type\":\"close\"}",
        "{\"type\":\"close\"}\n{\"type\":\"close\"}", "{\"type\":\"close\"}\r",
        "{\"type\":\"request\",\"id\":01,\"args\":[\"status\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[[[[[[[[[\"status\"]]]]]]]]]}", NULL
    };
    for (guint i = 0; invalid[i]; i++) {
        Message parsed = {0};
        g_test_message("reject %u", i);
        g_assert_false(parse_message(invalid[i], strlen(invalid[i]), &parsed));
        g_assert_null(parsed.argv);
    }
    gchar *long_line = g_strnfill(RECORD_LIMIT + 1, ' ');
    Message parsed = {0};
    g_assert_false(parse_message(long_line, RECORD_LIMIT + 1, &parsed));
    g_free(long_line);
}

static void test_guided_requests(void)
{
    const gchar *valid[] = {
        "{\"type\":\"request\",\"id\":1,\"args\":[\"access\",\"list\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"access\",\"allow\",\"home\",\"80,443\",\"tcp\",\"192.168.1.0/24\",\"wlan0\",\"60\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"access\",\"update\",\"home\",\"g1-2-3\",\"80,443\",\"tcp\",\"2001:db8::/64\",\"eth0\",\"10080\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"access\",\"revoke\",\"home\",\"g1-2-3\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"connections\",\"set\",\"11111111-2222-3333-4444-555555555555\",\"autoconnect\",\"true\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"connections\",\"reconnect\",\"11111111-2222-3333-4444-555555555555\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"diagnostics\",\"show\",\"containers\"]}"
    };
    for (guint i = 0; i < G_N_ELEMENTS(valid); i++) {
        Message parsed = message(valid[i]);
        g_assert_cmpint(parsed.type, ==, MESSAGE_REQUEST);
        if (i == 2) {
            /* Nine command words survive the broker without truncation. */
            g_assert_cmpuint(g_strv_length(parsed.argv), ==, 11);
            g_assert_cmpstr(parsed.argv[10], ==, "10080");
            g_assert_null(parsed.argv[11]);
        }
        message_clear(&parsed);
    }
    const gchar *invalid[] = {
        "{\"type\":\"request\",\"id\":1,\"args\":[\"access\",\"update\",\"home\",\"g1-2-3\",\"80,443\",\"tcp\",\"any\",\"any\",\"0\",\"extra\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"access\",\"allow\",\"home\",\"80,80\",\"tcp\",\"any\",\"any\",\"0\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"containers\",\"plan\",\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"]}",
        "{\"type\":\"request\",\"id\":1,\"args\":[\"containers\",\"localize\",\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"]}"
    };
    for (guint i = 0; i < G_N_ELEMENTS(invalid); i++) {
        Message parsed = {0};
        g_assert_false(parse_message(invalid[i], strlen(invalid[i]), &parsed));
        g_assert_null(parsed.argv);
        message_clear(&parsed);
    }
}

static void test_request_sequence(void)
{
    Broker broker;
    broker_init(&broker);
    Message first = message("{\"type\":\"request\",\"id\":1,\"args\":[\"status\"]}");
    Message second = message("{\"type\":\"request\",\"id\":2,\"args\":[\"status\"]}");
    g_assert_true(message_permitted(&broker, &first));
    g_assert_false(message_permitted(&broker, &second));
    broker.child = 10;
    g_assert_false(message_permitted(&broker, &first));
    broker.child = 0;
    broker.next_request = 2;
    g_assert_false(message_permitted(&broker, &first));
    g_assert_true(message_permitted(&broker, &second));
    broker_revoke(&broker, "test");
    g_assert_false(message_permitted(&broker, &second));
    message_clear(&first); message_clear(&second);
    broker_clear(&broker);
}

static void test_answer_binding(void)
{
    Broker broker;
    broker_init(&broker);
    Message answer = message("{\"type\":\"answer\",\"request\":2,\"id\":3,\"allow\":true}");
    g_assert_false(message_permitted(&broker, &answer));
    int pipefd[2];
    g_assert_cmpint(pipe2(pipefd, O_CLOEXEC), ==, 0);
    broker.child = 10; broker.request = 2; broker.prompt = 3;
    broker.child_input = pipefd[1];
    g_assert_true(message_permitted(&broker, &answer));
    answer.request = 1;
    g_assert_false(message_permitted(&broker, &answer));
    answer.request = 2; answer.prompt = 2;
    g_assert_false(message_permitted(&broker, &answer));
    answer.prompt = 3; broker.prompt = 0;
    g_assert_false(message_permitted(&broker, &answer));
    broker.prompt = 3; broker.child_exited = TRUE;
    g_assert_false(message_permitted(&broker, &answer));
    broker.child_exited = FALSE;
    broker_revoke(&broker, "locked");
    g_assert_false(message_permitted(&broker, &answer));
    gchar byte;
    g_assert_cmpint(read(pipefd[0], &byte, 1), ==, 0);
    close_fd(&pipefd[0]);
    message_clear(&answer);
    broker_clear(&broker);
}

static void test_exact_answer_delivery(void)
{
    Broker broker;
    broker_init(&broker);
    int pipefd[2];
    g_assert_cmpint(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK), ==, 0);
    broker.child = 10; broker.request = 2; broker.prompt = 3;
    broker.child_input = pipefd[1];
    Message answer = message("{\"type\":\"answer\",\"request\":2,\"id\":3,\"allow\":true}");
    g_assert_true(message_permitted(&broker, &answer));
    deliver_answer(&broker, &answer);
    gchar result[32] = {0};
    g_assert_cmpint(read(pipefd[0], result, sizeof(result) - 1), ==, 6);
    g_assert_cmpstr(result, ==, "3 yes\n");
    g_assert_false(message_permitted(&broker, &answer));
    broker.prompt = answer.prompt = 4; answer.allow = FALSE;
    deliver_answer(&broker, &answer);
    memset(result, 0, sizeof(result));
    g_assert_cmpint(read(pipefd[0], result, sizeof(result) - 1), ==, 5);
    g_assert_cmpstr(result, ==, "4 no\n");
    close_fd(&pipefd[0]);
    broker.prompt = answer.prompt = 5;
    deliver_answer(&broker, &answer);
    g_assert_true(broker.revoked);
    g_assert_cmpuint(broker.prompt, ==, 0);
    message_clear(&answer);
    broker_clear(&broker);
}

static void test_streaming(void)
{
    Broker broker;
    broker_init(&broker);
    broker.request = 7;
    const gchar *first = "{\"type\":\"log\",\"text\":\"hello\"}\n{\"type\":\"con";
    g_assert_true(consume_lines(&broker, broker.child_line, first, strlen(first), FALSE));
    const gchar *second = "firm\",\"text\":\"Allow?\",\"id\":1}\n";
    g_assert_true(consume_lines(&broker, broker.child_line, second, strlen(second), FALSE));
    g_assert_cmpuint(broker.prompt, ==, 1);
    g_assert_nonnull(strstr(broker.pending->str, "\"request\":7"));
    const gchar *replay = "{\"type\":\"confirm\",\"text\":\"Again?\",\"id\":1}";
    g_assert_false(forward_event(&broker, replay, strlen(replay)));
    broker.prompt = 0;
    g_assert_false(forward_event(&broker, replay, strlen(replay)));
    const gchar *done = "{\"type\":\"done\",\"success\":true}";
    g_assert_true(forward_event(&broker, done, strlen(done)));
    g_assert_false(forward_event(&broker, done, strlen(done)));
    broker_clear(&broker);
}

static void test_bounded_stream(void)
{
    Broker broker;
    broker_init(&broker);
    gchar *oversized = g_strnfill(RECORD_LIMIT + 1, 'x');
    g_assert_false(consume_lines(&broker, broker.child_line, oversized, RECORD_LIMIT + 1, FALSE));
    g_assert_cmpuint(broker.child_line->len, ==, RECORD_LIMIT);
    g_free(oversized);
    g_string_truncate(broker.child_line, 0);
    g_assert_false(consume_lines(&broker, broker.child_line, "x\0y", 3, FALSE));
    JsonObject *event = event_object("log", 1);
    gchar *text = g_strnfill(4000, 'x');
    json_object_set_string_member(event, "text", text);
    guint count = 0;
    while (queue_event(&broker, event)) count++;
    g_assert_cmpuint(count, >, 1);
    g_assert_cmpuint(broker.pending->len, <=, QUEUE_LIMIT);
    json_object_unref(event); g_free(text);
    broker_revoke(&broker, "backpressure");
    g_assert_cmpuint(broker.pending->len, <, 200);
    broker_clear(&broker);
}

static void test_completion_change_state(void)
{
    const gchar *states[] = {NULL, "false", "true", "\"false\"", "null", "0", "[]", "{}"};
    for (guint i = 0; i < G_N_ELEMENTS(states); i++) {
        Broker broker;
        broker_init(&broker);
        broker.request = 7;
        g_autofree gchar *record = states[i] == NULL ?
            g_strdup("{\"type\":\"done\",\"success\":false}") :
            g_strdup_printf("{\"type\":\"done\",\"success\":false,\"change_started\":%s}", states[i]);
        gboolean valid = i < 3;
        g_assert_cmpint(forward_event(&broker, record, strlen(record)), ==, valid);
        g_assert_cmpint(broker.done_seen, ==, valid);
        if (!valid) {
            g_assert_cmpuint(broker.pending->len, ==, 0);
        } else {
            g_autoptr(JsonParser) parser = json_parser_new();
            g_assert_true(json_parser_load_from_data(parser, broker.pending->str, -1, NULL));
            JsonObject *event = json_node_get_object(json_parser_get_root(parser));
            g_assert_cmpint(json_object_get_int_member(event, "request"), ==, 7);
            g_assert_false(json_object_get_boolean_member(event, "success"));
            g_assert_cmpint(json_object_has_member(event, "change_started"), ==, states[i] != NULL);
            if (states[i] != NULL) {
                JsonNode *state = json_object_get_member(event, "change_started");
                g_assert_cmpuint(json_node_get_value_type(state), ==, G_TYPE_BOOLEAN);
                g_assert_cmpint(json_node_get_boolean(state), ==, g_str_equal(states[i], "true"));
            }
        }
        broker_clear(&broker);
    }
}

static void test_structured_stream(void)
{
    Broker broker;
    broker_init(&broker);
    broker.request = 19;
    g_autofree gchar *padding = g_strnfill(8192, 'x');
    g_autofree gchar *document = g_strdup_printf(
        "{\"kind\":\"diagnostics\",\"name\":\"<b>name</b>\342\200\256\",\"escaped\":\"\\r\\t\\u001b\",\"padding\":\"%s\"}", padding);
    g_autoptr(JsonObject) data = json_object_new();
    json_object_set_string_member(data, "type", "data");
    json_object_set_string_member(data, "text", document);
    g_autoptr(JsonNode) node = json_node_new(JSON_NODE_OBJECT);
    json_node_set_object(node, data);
    g_autofree gchar *record = json_to_string(node, FALSE);
    g_autofree gchar *line = g_strconcat(record, "\n", NULL);
    g_assert_cmpuint(strlen(line), >, 8192);
    g_assert_true(consume_lines(&broker, broker.child_line, line, 4093, FALSE));
    g_assert_cmpuint(broker.pending->len, ==, 0);
    g_assert_true(consume_lines(&broker, broker.child_line, line + 4093, strlen(line) - 4093, FALSE));
    g_assert_cmpuint(broker.child_line->len, ==, 0);
    g_assert_false(broker.done_seen);
    g_assert_cmpuint(broker.prompt, ==, 0);
    g_autoptr(JsonParser) parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, broker.pending->str, -1, NULL));
    JsonObject *forwarded = json_node_get_object(json_parser_get_root(parser));
    g_assert_cmpstr(json_object_get_string_member(forwarded, "type"), ==, "data");
    g_assert_cmpint(json_object_get_int_member(forwarded, "request"), ==, 19);
    g_assert_cmpstr(json_object_get_string_member(forwarded, "text"), ==, document);
    g_assert_false(json_object_has_member(forwarded, "success"));
    const gchar *confirm = "{\"type\":\"confirm\",\"id\":1,\"text\":\"Review complete?\"}";
    g_assert_true(forward_event(&broker, confirm, strlen(confirm)));
    g_assert_cmpuint(broker.prompt, ==, 1);
    broker.prompt = 0;
    const gchar *done = "{\"type\":\"done\",\"success\":true}";
    g_assert_true(forward_event(&broker, done, strlen(done)));
    g_assert_true(broker.done_seen);
    g_assert_false(forward_event(&broker, record, strlen(record)));
    broker_clear(&broker);
}

static GVariant *properties(guint32 uid, gboolean active, gboolean remote, gboolean locked, const gchar *type)
{
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&builder, "{sv}", "User", g_variant_new("(uo)", uid, "/user/1"));
    g_variant_builder_add(&builder, "{sv}", "Active", g_variant_new_boolean(active));
    g_variant_builder_add(&builder, "{sv}", "Remote", g_variant_new_boolean(remote));
    g_variant_builder_add(&builder, "{sv}", "LockedHint", g_variant_new_boolean(locked));
    g_variant_builder_add(&builder, "{sv}", "Type", g_variant_new_string(type));
    return g_variant_ref_sink(g_variant_builder_end(&builder));
}

static void test_authority_properties(void)
{
    const struct {gboolean active, remote, locked; const gchar *type; guint32 uid; gboolean valid;} cases[] = {
        {TRUE, FALSE, FALSE, "wayland", 1000, TRUE},
        {TRUE, FALSE, FALSE, "x11", 1000, TRUE},
        {FALSE, FALSE, FALSE, "wayland", 1000, FALSE},
        {TRUE, TRUE, FALSE, "wayland", 1000, FALSE},
        {TRUE, FALSE, TRUE, "wayland", 1000, FALSE},
        {TRUE, FALSE, FALSE, "tty", 1000, FALSE},
        {TRUE, FALSE, FALSE, "wayland", 1001, FALSE},
        {TRUE, FALSE, FALSE, "wayland", 0, FALSE}
    };
    for (guint i = 0; i < G_N_ELEMENTS(cases); i++) {
        GVariant *p = properties(cases[i].uid, cases[i].active, cases[i].remote, cases[i].locked, cases[i].type);
        g_assert_cmpint(session_properties(p, 1000), ==, cases[i].valid);
        g_variant_unref(p);
    }
    GVariant *empty = g_variant_ref_sink(g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0));
    g_assert_false(session_properties(empty, 1000));
    g_variant_unref(empty);
    uid_t uid = 0;
    g_assert_true(parse_uid("1000", &uid));
    g_assert_cmpuint(uid, ==, 1000);
    const gchar *invalid[] = {NULL, "", "0", "01", "-1", "+1", "1x", "4294967295", "99999999999"};
    for (guint i = 0; i < G_N_ELEMENTS(invalid); i++) g_assert_false(parse_uid(invalid[i], &uid));
    gchar *path = g_strdup_printf("/proc/%ld/status", (long)getpid());
    if (access(path, R_OK) == 0) g_assert_true(parent_uid(getpid(), getuid()));
    else g_test_message("Executor PID namespace is not mounted at /proc; real UID parser checked in CI.");
    g_free(path);
    g_assert_false(parent_uid(getpid(), getuid() + 1));
}

static void test_executable_identity(void)
{
    struct stat initial = {.st_mode = S_IFREG | 0755, .st_uid = 0, .st_nlink = 1, .st_dev = 1, .st_ino = 100};
    struct stat current = initial;
    g_assert_true(executable_matches(&initial, &current));
    current.st_ino++;
    g_assert_false(executable_matches(&initial, &current));
    current = initial; current.st_dev++;
    g_assert_false(executable_matches(&initial, &current));
    current = initial; current.st_nlink = 0;
    g_assert_false(executable_matches(&initial, &current));
    current = initial; current.st_uid = 1000;
    g_assert_false(executable_matches(&initial, &current));
    current = initial; current.st_mode |= S_IWGRP;
    g_assert_false(executable_matches(&initial, &current));
    current = initial; current.st_mode = S_IFLNK | 0777;
    g_assert_false(executable_matches(&initial, &current));
}

static void test_parent_death(void)
{
    int child_input[2];
    g_assert_cmpint(pipe2(child_input, O_CLOEXEC), ==, 0);
    pid_t child = fork();
    g_assert_cmpint(child, >=, 0);
    if (child == 0) {
        (void)close(child_input[1]);
        char byte;
        ssize_t ignored = read(child_input[0], &byte, 1);
        (void)ignored;
        _exit(0);
    }
    close_fd(&child_input[0]);
    Authority authority = {.parent_fd = (int)syscall(SYS_pidfd_open, child, 0)};
    g_assert_cmpint(authority.parent_fd, >=, 0);
    g_assert_true(parent_alive(&authority));
    close_fd(&child_input[1]);
    g_assert_cmpint(waitpid(child, NULL, 0), ==, child);
    g_assert_false(parent_alive(&authority));
    close_fd(&authority.parent_fd);
}

static void test_revocation_pending_child(void)
{
    Broker broker;
    broker_init(&broker);
    int input[2], output[2], error[2];
    g_assert_cmpint(pipe2(input, O_CLOEXEC), ==, 0);
    g_assert_cmpint(pipe2(output, O_CLOEXEC), ==, 0);
    g_assert_cmpint(pipe2(error, O_CLOEXEC), ==, 0);
    broker.child = fork();
    g_assert_cmpint(broker.child, >=, 0);
    if (broker.child == 0) {
        (void)close(input[1]); (void)close(output[0]); (void)close(error[0]);
        char answer[32];
        ssize_t count = read(input[0], answer, sizeof(answer));
        _exit(count == 0 ? 0 : 42);
    }
    close_fd(&input[0]); close_fd(&output[1]); close_fd(&error[1]);
    broker.child_input = input[1]; broker.child_output = output[0]; broker.child_error = error[0];
    broker.request = 1; broker.prompt = 1;
    broker_revoke(&broker, "The application disconnected.");
    g_assert_cmpint(broker.child_input, ==, -1);
    g_assert_cmpint(waitpid(broker.child, &broker.child_status, 0), ==, broker.child);
    g_assert_true(WIFEXITED(broker.child_status));
    g_assert_cmpint(WEXITSTATUS(broker.child_status), ==, 0);
    read_child(&broker, FALSE); read_child(&broker, TRUE);
    g_assert_true(finish_child(&broker));
    g_assert_cmpint(broker.child, ==, 0);
    g_assert_null(strstr(broker.pending->str, "finished"));
    broker_clear(&broker);
}

static void test_completion_waits_for_both_eofs(void)
{
    Broker broker;
    broker_init(&broker);
    int output[2], error[2];
    g_assert_cmpint(pipe2(output, O_CLOEXEC), ==, 0);
    g_assert_cmpint(pipe2(error, O_CLOEXEC), ==, 0);
    broker.child = 123; broker.child_exited = TRUE; broker.child_status = 0;
    broker.child_output = output[0]; broker.child_error = error[0]; broker.request = 8;
    const gchar *done = "{\"type\":\"done\",\"success\":true}\n";
    g_assert_cmpint(write(output[1], done, strlen(done)), ==, (ssize_t)strlen(done));
    close_fd(&output[1]);
    read_child(&broker, FALSE);
    g_assert_true(broker.done_seen);
    g_assert_false(finish_child(&broker));
    read_child(&broker, FALSE);
    g_assert_false(finish_child(&broker));
    const gchar *untrusted = "{\"type\":\"confirm\",\"id\":9}\033[31m";
    g_assert_cmpint(write(error[1], untrusted, strlen(untrusted)), ==, (ssize_t)strlen(untrusted));
    read_child(&broker, TRUE);
    g_assert_nonnull(strstr(broker.pending->str, "\"type\":\"stderr\",\"request\":8"));
    g_assert_null(strstr(broker.pending->str, "\"type\":\"confirm\""));
    g_assert_cmpuint(broker.prompt, ==, 0);
    close_fd(&error[1]);
    read_child(&broker, TRUE);
    g_assert_true(finish_child(&broker));
    g_assert_nonnull(strstr(broker.pending->str, "\"type\":\"finished\",\"request\":8,\"exit_code\":0"));
    broker_clear(&broker);
}

static void test_disconnect_and_invalid_command(void)
{
    Broker broker;
    broker_init(&broker);
    receive_message(&broker, "{\"type\":\"request\",\"id\":1,\"args\":[\"sh\"]}", 39);
    g_assert_true(broker.revoked);
    g_assert_cmpint(broker.child, ==, 0);
    broker_clear(&broker);
    broker_init(&broker);
    int input[2];
    g_assert_cmpint(pipe2(input, O_CLOEXEC), ==, 0);
    broker.input = input[0];
    close_fd(&input[1]);
    read_input(&broker);
    g_assert_true(broker.revoked);
    close_fd(&input[0]);
    broker_clear(&broker);
}

int main(int argc, char **argv)
{
    /* Compile every production path with the same strict warnings. Tests call
     * only pure parsers and harmless pipe/child fixtures, never native policy. */
    (void)authority_init;
    (void)broker_run;
    (void)signal(SIGPIPE, SIG_IGN);
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/session/requests", test_requests);
    g_test_add_func("/session/bound-usb-requests", test_bound_usb_requests);
    g_test_add_func("/session/guided-requests", test_guided_requests);
    g_test_add_func("/session/rejections", test_rejections);
    g_test_add_func("/session/request-sequence", test_request_sequence);
    g_test_add_func("/session/answer-binding", test_answer_binding);
    g_test_add_func("/session/streaming", test_streaming);
    g_test_add_func("/session/completion-change-state", test_completion_change_state);
    g_test_add_func("/session/exact-answer-delivery", test_exact_answer_delivery);
    g_test_add_func("/session/bounded-stream", test_bounded_stream);
    g_test_add_func("/session/structured-stream", test_structured_stream);
    g_test_add_func("/session/authority-properties", test_authority_properties);
    g_test_add_func("/session/parent-death", test_parent_death);
    g_test_add_func("/session/executable-identity", test_executable_identity);
    g_test_add_func("/session/revocation-pending-child", test_revocation_pending_child);
    g_test_add_func("/session/completion-eofs", test_completion_waits_for_both_eofs);
    g_test_add_func("/session/disconnection", test_disconnect_and_invalid_command);
    return g_test_run();
}
