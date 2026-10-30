#!/usr/bin/env python3
"""One-use, assertion-checked source edits for the 1.3.4 fix branch."""
from pathlib import Path
import subprocess


def replace(text, old, new, count=1):
    if text.count(old) != count:
        raise RuntimeError(f"Expected {count} copies of {old[:110]!r}, found {text.count(old)}")
    return text.replace(old, new)


path = Path('src/ui/octoshield-gtk.c')
s = path.read_text()
s = replace(s, '#define MAX_REVIEW_BYTES (256U * 1024U)', '#define MAX_REVIEW_BYTES (256U * 1024U)\n#define PRIVATE_INSPECTION_MAX_AGE (30 * G_TIME_SPAN_SECOND)')
s = replace(s, '    gboolean changes;\n} Request;', '    gboolean changes;\n    gboolean automatic;\n} Request;')
s = replace(s, '    gboolean firewall_change;\n    guint64 request_id;', '    gboolean firewall_change;\n    gboolean connection_change;\n    gboolean access_change;\n    gboolean automatic;\n    guint inspection;\n    guint64 request_id;')
s = replace(s, '    guint private_refresh;\n    guint private_refresh_idle;', '    guint private_refresh;\n    guint private_refresh_manual;\n    guint private_refresh_idle;\n    gint64 access_checked_at;\n    gint64 connections_checked_at;')
s = replace(s, '    GtkTextIter end;\n    gtk_text_buffer_get_end_iter(app->log, &end);', '    /* Keep successful background reads out of the preceding user action.\n     * The bounded review buffer retains their diagnostics if they fail. */\n    if (app->operation != NULL && app->operation->automatic) return;\n    GtkTextIter end;\n    gtk_text_buffer_get_end_iter(app->log, &end);')
anchor = 'static void protocol_error(Operation *operation, const char *message)\n'
s = replace(s, anchor, '''static void operation_present_details(Operation *operation)
{
    if (!operation->automatic) return;
    operation->automatic = FALSE;
    App *app = operation->app;
    g_autofree gchar *details = g_strdup(operation->review->str);
    gtk_text_buffer_set_text(app->log, "", 0);
    append_log(app, operation->title);
    append_log(app, details);
    gtk_expander_set_expanded(app->details, TRUE);
}

''' + anchor)
s = replace(s, '    if (!operation->protocol_failed) {\n        operation->protocol_failed = TRUE;', '    operation_present_details(operation);\n    if (!operation->protocol_failed) {\n        operation->protocol_failed = TRUE;')
s = replace(s, '    operation->waiting_confirmation = TRUE;\n    operation->current_prompt_id = id;', '    operation_present_details(operation);\n    operation->waiting_confirmation = TRUE;\n    operation->current_prompt_id = id;')
s = replace(s, '''    gboolean changed_access = g_str_equal(operation->title, "Allow network access") ||
        g_str_equal(operation->title, "Update network access") || g_str_equal(operation->title, "Revoke network access");''', '    gboolean changed_access = operation->access_change;')
s = replace(s, '''    gboolean changed_connection = g_str_equal(operation->title, "Save connection privacy") ||
        g_str_equal(operation->title, "Reconnect selected network") || g_str_equal(operation->title, "Review external network changes");''', '    gboolean changed_connection = operation->connection_change;')
s = replace(s, '''    operation->waiting_confirmation = FALSE;
    if (app->confirmation != NULL) {''', '''    if (!success) {
        app->private_refresh_manual = 0;
        operation_present_details(operation);
    } else {
        /* A successful exit alone is not a valid inspection: data_seen above
         * is set only after structured result validation and rendering. */
        if (operation->inspection == 1U && app->access_loaded)
            app->access_checked_at = g_get_monotonic_time();
        if (operation->inspection == 2U && app->connections_loaded)
            app->connections_checked_at = g_get_monotonic_time();
    }
    operation->waiting_confirmation = FALSE;
    if (app->confirmation != NULL) {''')
s = replace(s, '''        gtk_label_set_text(app->activity, "Operation completed — review the details below");
        append_log(app, "Operation completed successfully.");
        toast(app, "Operation completed");''', '''        if (!operation->automatic) {
            gtk_label_set_text(app->activity, "Operation completed — review the details below");
            append_log(app, "Operation completed successfully.");
            toast(app, "Operation completed");
        }''')
s = replace(s, '    if (changed_connection) app->private_refresh |= 2U;', '''    if (changed_connection) {
        app->connections_loaded = FALSE;
        app->connections_checked_at = 0;
        app->private_refresh |= 2U;
    }''')
anchor = 'static void launch_request(Request *request)\n{'
s = replace(s, anchor, '''/* Resource invalidation follows allowlisted commands, never UI wording.
 * Attempted mutations also invalidate on partial/uncertain failure. */
static guint changed_private_resources(gsize count, const gchar *const *args)
{
    if (count < 2) return 0;
    if (g_str_equal(args[0], "access")) return 1U;
    if (g_str_equal(args[0], "connections")) return 2U;
    if (g_str_equal(args[0], "apply") || g_str_equal(args[0], "office")) {
        if (g_str_equal(args[1], "firewall")) return 1U;
        if (g_str_equal(args[1], "network")) return 2U;
    }
    if (!g_str_equal(args[0], "profile")) return 0;
    if (g_str_equal(args[1], "apply") || g_str_equal(args[1], "restore")) {
        gsize control = g_str_equal(args[1], "apply") ? 3 : 2;
        if (count == control) return 3U;
        if (count > control && g_str_equal(args[control], "firewall")) return 1U;
        if (count > control && g_str_equal(args[control], "network")) return 2U;
    }
    if (g_str_equal(args[1], "rule-add") || g_str_equal(args[1], "rule-remove")) return 1U;
    if (g_str_equal(args[1], "set") && count >= 4 && g_str_has_prefix(args[3], "network.")) return 2U;
    if (g_str_equal(args[1], "create") || g_str_equal(args[1], "delete")) return 3U;
    return 0;
}

''' + anchor)
a = s.index('    if (privileged && request->changes) {', s.index(anchor))
b = s.index('    operation->answers =', a)
s = s[:a] + '''    if (privileged) {
        const gchar *const *args = (const gchar *const *)&request->argv[2];
        gsize count = g_strv_length(request->argv) - 2;
        if (request->changes) {
            guint changed = changed_private_resources(count, args);
            operation->firewall_change = (changed & 1U) != 0;
            operation->connection_change = (changed & 2U) != 0;
            operation->access_change = count >= 2 && g_str_equal(args[0], "access") &&
                (g_str_equal(args[1], "allow") || g_str_equal(args[1], "update") || g_str_equal(args[1], "revoke"));
            if (operation->connection_change) {
                app->connections_loaded = FALSE;
                app->connections_checked_at = 0;
            }
        } else if (count >= 2 && g_str_equal(args[1], "list")) {
            if (g_str_equal(args[0], "access")) operation->inspection = 1U;
            if (g_str_equal(args[0], "connections")) operation->inspection = 2U;
        } else if (count == 3 && g_str_equal(args[0], "diagnostics") && g_str_equal(args[1], "show")) {
            operation->inspection = 4U;
        }
    }
    operation->automatic = request->automatic && !request->changes && operation->inspection != 0;
''' + s[b:]
s = replace(s, '''    gtk_text_buffer_set_text(app->log, "", 0);
    append_log(app, request->title);
    if (request->impact != NULL)
        append_log(app, request->impact);
    append_log(app, "Review this output and every requested confirmation. Closing this window does not interrupt a running system change.");
    gtk_expander_set_expanded(app->details, TRUE);
    gtk_label_set_text(app->activity, "Working — your administrator session is unlocked…");''', '''    if (!operation->automatic) {
        gtk_text_buffer_set_text(app->log, "", 0);
        append_log(app, request->title);
        if (request->impact != NULL) append_log(app, request->impact);
        append_log(app, request->changes ?
            "Review this output and every requested confirmation. Closing this window does not interrupt a running system change." :
            "Read-only inspection. This operation does not change protection settings.");
        gtk_expander_set_expanded(app->details, TRUE);
        gtk_label_set_text(app->activity, "Working — your administrator session is unlocked…");
    }''')
s = replace(s, '    app->access_loaded = FALSE; app->connections_loaded = FALSE; app->private_refresh = 0;', '''    app->access_loaded = FALSE; app->connections_loaded = FALSE; app->private_refresh = 0;
    app->private_refresh_manual = 0;
    app->access_checked_at = 0; app->connections_checked_at = 0;''')
s = replace(s, '''static void start_action(App *app, const char *title, const char *impact, gboolean privileged,
                         gboolean changes, gsize argc, const char *const *args)''', '''static void start_action_full(App *app, const char *title, const char *impact, gboolean privileged,
                              gboolean changes, gsize argc, const char *const *args, gboolean automatic)''')
s = replace(s, '    request->changes = changes;\n', '    request->changes = changes;\n    request->automatic = automatic;\n')
anchor = 'static void fixed_action_clicked(GtkButton *button, gpointer data)'
s = replace(s, anchor, '''static void start_action(App *app, const char *title, const char *impact, gboolean privileged,
                         gboolean changes, gsize argc, const char *const *args)
{
    start_action_full(app, title, impact, privileged, changes, argc, args, FALSE);
}

''' + anchor)
a = s.index('static gboolean refresh_private(gpointer data)\n{')
b = s.index('static void connections_refresh_clicked', a)
s = s[:a] + '''/* A cache only avoids redundant page reads. Every mutation still uses the
 * helper's fresh locked assessment; this is never authority to change policy. */
static gboolean private_inspection_current(App *app, guint resource)
{
    gint64 checked = resource == 1U ? app->access_checked_at : app->connections_checked_at;
    gboolean loaded = resource == 1U ? access_current(app) : app->connections_loaded;
    gint64 age = g_get_monotonic_time() - checked;
    return checked > 0 && loaded && age >= 0 && age < PRIVATE_INSPECTION_MAX_AGE;
}

static gboolean refresh_private(gpointer data)
{
    App *app = data;
    app->private_refresh_idle = 0;
    if (app->shutting_down || app->smoke_test || !administrator_ready(app)) {
        app->private_refresh = 0;
        app->private_refresh_manual = 0;
        return G_SOURCE_REMOVE;
    }
    if (app->operation != NULL || app->preview != NULL || app->usb_prompt != NULL) return G_SOURCE_REMOVE;
    /* Recheck automatic requests at dispatch: a preceding operation may have
     * already supplied the result while this request was queued. */
    for (guint resource = 1U; resource <= 2U; resource <<= 1)
        if (!(app->private_refresh_manual & resource) && private_inspection_current(app, resource))
            app->private_refresh &= ~resource;
    guint resource = (app->private_refresh & 1U) ? 1U : (app->private_refresh & 2U) ? 2U : (app->private_refresh & 4U);
    if (resource == 0) return G_SOURCE_REMOVE;
    gboolean automatic = !(app->private_refresh_manual & resource);
    app->private_refresh &= ~resource;
    app->private_refresh_manual &= ~resource;
    if (resource == 1U) {
        const char *profile = app->access_profile_initialized ? selected_profile(app, app->access_profile) : NULL;
        const char *args[] = {"access", "list", profile};
        start_action_full(app, "Refresh access permissions", NULL, TRUE, FALSE, profile != NULL ? 3 : 2, args, automatic);
    } else if (resource == 2U) {
        const char *args[] = {"connections", "list"};
        start_action_full(app, "Refresh connections", NULL, TRUE, FALSE, G_N_ELEMENTS(args), args, automatic);
    } else {
        const char *args[] = {"diagnostics", "show", "containers"};
        start_action_full(app, "Review protection details", NULL, TRUE, FALSE, G_N_ELEMENTS(args), args, automatic);
    }
    return G_SOURCE_REMOVE;
}

static void queue_private_refresh(App *app, guint flags)
{
    app->private_refresh |= flags;
    app->private_refresh_manual |= flags;
    if (app->private_refresh_idle == 0) app->private_refresh_idle = g_idle_add(refresh_private, app);
}

static void ensure_private_refresh(App *app, guint flags)
{
    if (app->shutting_down || app->smoke_test || !administrator_ready(app)) return;
    for (guint resource = 1U; resource <= 2U; resource <<= 1) {
        if (!(flags & resource) || private_inspection_current(app, resource)) continue;
        if (app->operation != NULL && app->operation->inspection == resource) continue;
        app->private_refresh |= resource;
    }
    if (app->private_refresh != 0 && app->private_refresh_idle == 0)
        app->private_refresh_idle = g_idle_add(refresh_private, app);
}

static void access_refresh_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    queue_private_refresh(app, 1U);
    ensure_private_refresh(app, 2U);
}

''' + s[b:]
s = replace(s, 'if (g_str_equal(page, "office")) queue_private_refresh(app, 3U);\n            else if (g_str_equal(page, "privacy")) queue_private_refresh(app, 2U);', 'if (g_str_equal(page, "office")) ensure_private_refresh(app, 3U);\n            else if (g_str_equal(page, "privacy")) ensure_private_refresh(app, 2U);')
s = replace(s, '        queue_private_refresh(app, 3U);\n        return;', '        queue_private_refresh(app, 1U);\n        ensure_private_refresh(app, 2U);\n        return;')
path.write_text(s)

path = Path('scripts/version.sh')
s = path.read_text()
s = replace(s, '        patch) patch=$(version::increment "$patch") ;;', '''        patch)
            if [[ $patch == 9 ]]; then
                minor=$(version::increment "$minor")
                patch=0
            else patch=$(version::increment "$patch"); fi
            ;;''')
path.write_text(s)
subprocess.run(['bash', 'scripts/version.sh', '--set', '1.3.4'], check=True)
path = Path('debian/changelog')
s = path.read_text()
s = replace(s, '  * Prepare release 1.3.4; review release notes before tagging.', '''  * Ship the verified Office firewall access-readiness fix from 1.3.3's
    follow-up changes; retain scoped access when original restoration is absent.
  * Reuse fresh inspections on navigation and coalesce pending and running reads.
  * Keep successful automatic inspections quiet and preserve user change output.
  * Refresh after network/profile changes, including uncertain failures and locks.
  * Test permanent TCP 9003 access with real UFW and unavailable restore evidence.
  * Keep maintenance versions patch-sized, carrying 1.3.9 into 1.4.0.''')
path.write_text(s)
path = Path('data/io.vdm.OctoShield.metainfo.xml')
s = path.read_text()
s = replace(s, '<description><p>Release preparation; review the release notes before publication.</p></description>', '<description><p>Fix verified firewall access readiness and repeated connection refreshes when navigating. Preserve operation details during automatic inspections, refresh after protection changes, and deliver the fixes as maintenance release 1.3.4.</p></description>')
path.write_text(s)

path = Path('tests/firewall-integration.sh')
s = path.read_text()
s = replace(s, 'for port in 80 443 9000; do', 'for port in 80 443 9000 9003; do', count=2)
s = replace(s, "( sport = :80 or sport = :443 or sport = :9000 )", "( sport = :80 or sport = :443 or sport = :9000 or sport = :9003 )", count=2)
s = replace(s, '| wc -l) == 6 ]]', '| wc -l) == 8 ]]', count=2)
s = replace(s, '    ip route add 198.51.100.2/32 dev octolan0', '    ip netns exec octolan ip address add 172.24.0.4/32 dev peerlan\n    ip route add 172.24.0.4/32 dev octolan0\n    ip route add 198.51.100.2/32 dev octolan0')
anchor = "    FIREWALL_TEST_CASE='permanent scoped web access, reload and grouped revocation'"
s = replace(s, anchor, '''    FIREWALL_TEST_CASE='verified Office permits scoped TCP 9003 without its original restore point'
    directory=$(profile_controls::_directory)
    mv "$directory/firewall-baseline" "$directory/retained-baseline-test"
    saved_before=$(profile_controls::snapshot firewall)
    document_before=$(profiles::state)
    firewall_test::assert_ready
    access::list office | jq --exit-status '.recovery.can_restore == false and .recovery.can_apply' >/dev/null
    firewall_test::expect_failure firewall_test::change access::dispatch restore
    [[ $(profile_controls::snapshot firewall) == "$saved_before" && $(profiles::state) == "$document_before" ]] || firewall_test::fail 'Unavailable original restoration changed policy.'
    FIREWALL_TEST_CONSENT=no
    firewall_test::expect_failure firewall_test::change access::dispatch allow office 9003 tcp 172.24.0.4 any 0
    FIREWALL_TEST_CONSENT=yes
    [[ $(profile_controls::snapshot firewall) == "$saved_before" && $(profiles::state) == "$document_before" ]] || firewall_test::fail 'Cancelled TCP 9003 review changed policy.'
    firewall_test::change access::dispatch allow office 9003 tcp 172.24.0.4 any 0
    firewall_test::assert_ready
    firewall_test::probe allowed octolan 4 172.24.0.4 192.168.77.1 9003
    firewall_test::probe blocked octolan 4 192.168.77.2 192.168.77.1 9003
    firewall_test::probe blocked octolan 6 fd42:77::2 fd42:77::1 9003
    web_group=$(access::list office | jq --exit-status --raw-output '.rules[] | select(.ports == "9003") | .id')
    firewall_test::change access::dispatch revoke office "$web_group"
    firewall_test::probe blocked octolan 4 172.24.0.4 192.168.77.1 9003
    [[ ! -e $directory/firewall-baseline ]] || firewall_test::fail 'Access fabricated an original restore point.'
    mv "$directory/retained-baseline-test" "$directory/firewall-baseline"
    [[ $(firewall_test::baseline_hash) == "$baseline_before" ]] || firewall_test::fail 'TCP 9003 management changed retained original evidence.'
    firewall_test::assert_ready
    access::list office | jq --exit-status '.recovery.can_restore' >/dev/null
    printf 'PASS: verified Office allows and revokes exact TCP 9003 source without an original restore point; cancellation and scope are enforced\\n'

''' + anchor)
path.write_text(s)

path = Path('tests/version.bats')
s = path.read_text() + '''

@test 'maintenance patch increments stay small and carry nine into the next minor' {
    run bash "$VERSION_REPO/scripts/version.sh" --set 900.3.3
    [ "$status" -eq 0 ]
    for version in 900.3.4 900.3.5 900.3.6 900.3.7 900.3.8 900.3.9 900.4.0; do
        run bash "$VERSION_REPO/scripts/version.sh" --bump patch
        [ "$status" -eq 0 ]
        run bash "$VERSION_REPO/scripts/version.sh" --check "v$version"
        [ "$status" -eq 0 ]
    done
}
'''
path.write_text(s)

path = Path('tests/ui-app-test.c')
s = path.read_text()
s = replace(s, '        g_assert_null(strstr(current_log, "Retained fixture error"));', '''        if (i == 0) g_assert_nonnull(strstr(current_log, "Retained fixture error"));
        else g_assert_null(strstr(current_log, "Retained fixture error"));''')
fixture = r'''static int refresh_session_fixture(void)
{
    fputs("{\"type\":\"ready\"}\n", stdout); fflush(stdout);
    char line[8192];
    guint count = 0;
    while (fgets(line, sizeof(line), stdin) != NULL) {
        g_autoptr(JsonParser) parser = json_parser_new();
        if (!json_parser_load_from_data(parser, line, -1, NULL)) return 70;
        JsonObject *request = json_node_get_object(json_parser_get_root(parser));
        gint64 id = json_object_get_int_member(request, "id");
        JsonArray *args = array_member(request, "args");
        if (args == NULL || json_array_get_length(args) < 2) return 71;
        const char *kind = json_array_get_string_element(args, 0);
        const char *command = json_array_get_string_element(args, 1);
        count++;
        g_usleep(60000); /* Navigate while a genuine asynchronous read is in flight. */
        gboolean success = TRUE;
        if (g_str_equal(kind, "connections") && g_str_equal(command, "list")) {
            fixture_text_event("data", id, count == 5 ? "{invalid" : "{\"kind\":\"connections\",\"connections\":[]}");
        } else if (g_str_equal(kind, "access") && g_str_equal(command, "list")) {
            const char *profile = json_array_get_length(args) > 2 ? json_array_get_string_element(args, 2) : "office";
            g_autoptr(JsonObject) result = access_fixture(profile, "ready", TRUE);
            g_autoptr(JsonNode) node = json_node_new(JSON_NODE_OBJECT);
            json_node_set_object(node, result);
            g_autoptr(JsonGenerator) generator = json_generator_new();
            json_generator_set_root(generator, node);
            g_autofree gchar *json = json_generator_to_data(generator, NULL);
            fixture_text_event("data", id, json);
        } else if (g_str_equal(kind, "profile") && g_str_equal(command, "apply")) {
            fixture_text_event("log", id, "Fixture failed network change; refresh its actual state.");
            success = FALSE;
        } else return 72;
        printf("{\"type\":\"done\",\"request\":%" G_GINT64_FORMAT ",\"success\":%s,\"change_started\":%s}\n", id, success ? "true" : "false", success ? "false" : "true");
        printf("{\"type\":\"finished\",\"request\":%" G_GINT64_FORMAT ",\"exit_code\":%d}\n", id, success ? 0 : 1);
        fflush(stdout);
    }
    return 0;
}

'''
s = replace(s, 'static int fixture(const char *name)\n{', fixture + 'static int fixture(const char *name)\n{\n    if (g_str_equal(name, "refresh-session")) return refresh_session_fixture();')
tests = r'''static void refresh_test_drain(void)
{
    gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while ((test_app.operation != NULL || test_app.private_refresh != 0 || test_app.private_refresh_idle != 0) &&
           g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
    g_assert_null(test_app.operation);
    g_assert_cmpuint(test_app.private_refresh, ==, 0);
    g_assert_cmpuint(test_app.private_refresh_idle, ==, 0);
}

static Session *refresh_test_open(void)
{
    const char *const argv[] = {test_executable, "--fixture", "refresh-session", NULL};
    g_autoptr(GError) error = NULL;
    Session *session = g_new0(Session, 1);
    session->app = &test_app;
    session->process = g_subprocess_newv(argv, G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE, &error);
    g_assert_no_error(error);
    session->input = g_subprocess_get_stdin_pipe(session->process);
    session->output = g_subprocess_get_stdout_pipe(session->process);
    session->line = g_byte_array_new();
    test_app.session = session; test_app.auth_required = TRUE;
    session_read_next(session);
    g_subprocess_wait_async(session->process, NULL, session_waited, session);
    gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (!session->ready && g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
    g_assert_true(session->ready);
    return session;
}

static void refresh_test_close(void)
{
    session_revoke(&test_app, "Refresh regression lock");
    gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (test_app.session != NULL && g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
    g_assert_null(test_app.session);
    g_assert_false(test_app.connections_loaded);
    g_assert_false(test_app.access_loaded);
    g_assert_cmpint(test_app.connections_checked_at, ==, 0);
    test_app.auth_required = FALSE;
    test_app.local_session_ready = FALSE;
    update_actions(&test_app);
}

static void test_refresh_navigation_and_failures(void)
{
    g_assert_null(test_app.operation);
    test_app.auth_required = FALSE;
    select_page(&test_app, "overview");
    select_access_profile("office");
    if (test_app.private_refresh_idle != 0) g_source_remove(test_app.private_refresh_idle);
    test_app.private_refresh_idle = 0; test_app.private_refresh = 0; test_app.private_refresh_manual = 0;
    test_app.access_loaded = FALSE; test_app.connections_loaded = FALSE;
    test_app.access_checked_at = 0; test_app.connections_checked_at = 0;
    gtk_text_buffer_set_text(test_app.log, "Previous reviewed Office operation", -1);
    gtk_expander_set_expanded(test_app.details, FALSE);
    Session *session = refresh_test_open();
    select_page(&test_app, "privacy");
    gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (test_app.operation == NULL && g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
    g_assert_nonnull(test_app.operation);
    g_assert_cmpuint(test_app.operation->inspection, ==, 2U);
    select_page(&test_app, "overview"); select_page(&test_app, "office"); select_page(&test_app, "privacy");
    refresh_test_drain();
    g_assert_cmpuint(session->next_request, ==, 2);
    g_assert_true(test_app.connections_loaded); g_assert_true(test_app.access_loaded);
    for (guint i = 0; i < 4; i++) { select_page(&test_app, "office"); select_page(&test_app, "privacy"); }
    refresh_test_drain();
    g_assert_cmpuint(session->next_request, ==, 2);
    g_assert_false(gtk_expander_get_expanded(test_app.details));
    g_autofree gchar *original = log_text();
    g_assert_cmpstr(original, ==, "Previous reviewed Office operation");

    connections_refresh_clicked(NULL, &test_app);
    refresh_test_drain();
    g_assert_cmpuint(session->next_request, ==, 3);
    g_assert_true(gtk_expander_get_expanded(test_app.details));
    g_autofree gchar *manual = log_text();
    g_assert_nonnull(strstr(manual, "Read-only inspection"));
    gtk_expander_set_expanded(test_app.details, FALSE);
    test_app.connections_checked_at = g_get_monotonic_time() - PRIVATE_INSPECTION_MAX_AGE - 1;
    select_page(&test_app, "overview"); select_page(&test_app, "privacy");
    refresh_test_drain();
    g_assert_cmpuint(session->next_request, ==, 4);
    g_autofree gchar *automatic = log_text();
    g_assert_cmpstr(automatic, ==, manual);
    g_assert_false(gtk_expander_get_expanded(test_app.details));

    /* The fifth response is malformed. A successful child exit cannot make
     * it current, and a later page visit must retry rather than cache failure. */
    test_app.connections_loaded = FALSE;
    select_page(&test_app, "overview"); select_page(&test_app, "privacy");
    refresh_test_drain();
    g_assert_cmpuint(session->next_request, ==, 5);
    g_assert_false(test_app.connections_loaded);
    g_assert_true(gtk_expander_get_expanded(test_app.details));
    g_autofree gchar *failure = log_text();
    g_assert_nonnull(strstr(failure, "could not be displayed safely"));
    gtk_expander_set_expanded(test_app.details, FALSE);
    select_page(&test_app, "overview"); select_page(&test_app, "privacy");
    refresh_test_drain();
    g_assert_cmpuint(session->next_request, ==, 6);
    g_assert_true(test_app.connections_loaded);
    g_autofree gchar *retained = log_text();
    g_assert_cmpstr(retained, ==, failure);

    const char *const args[] = {"profile", "apply", "office", "network"};
    start_action(&test_app, "A title unrelated to resource invalidation", NULL, TRUE, TRUE, G_N_ELEMENTS(args), args);
    g_assert_false(test_app.connections_loaded);
    refresh_test_drain();
    g_assert_cmpuint(session->next_request, ==, 8);
    g_assert_true(test_app.connections_loaded);
    g_autofree gchar *mutation = log_text();
    g_assert_nonnull(strstr(mutation, "Fixture failed network change"));
    refresh_test_close();

    select_page(&test_app, "overview");
    session = refresh_test_open();
    select_page(&test_app, "office");
    refresh_test_drain();
    g_assert_cmpuint(session->next_request, ==, 2);
    refresh_test_close();
}

static void test_refresh_resource_metadata(void)
{
    const struct { const char *args[6]; guint count; guint expected; } cases[] = {
        {{"profile", "apply", "office"}, 3, 3U},
        {{"profile", "restore"}, 2, 3U},
        {{"profile", "apply", "office", "network"}, 4, 2U},
        {{"profile", "restore", "network"}, 3, 2U},
        {{"profile", "apply", "office", "firewall"}, 4, 1U},
        {{"profile", "restore", "firewall"}, 3, 1U},
        {{"profile", "set", "office", "network.autoconnect", "false"}, 5, 2U},
        {{"connections", "reconcile"}, 2, 2U},
        {{"connections", "reconnect", "11111111-1111-1111-1111-111111111111"}, 3, 2U},
        {{"apply", "network"}, 2, 2U}, {{"office", "network", "uuid"}, 3, 2U},
        {{"access", "revoke", "office", "g1-2-3"}, 4, 1U},
        {{"profile", "apply", "office", "services"}, 4, 0U}
    };
    for (guint i = 0; i < G_N_ELEMENTS(cases); i++)
        g_assert_cmpuint(changed_private_resources(cases[i].count, cases[i].args), ==, cases[i].expected);
}

static void test_verified_access_without_original_restore(void)
{
    select_access_profile("office");
    access_cancel_edit(NULL, &test_app);
    g_autoptr(JsonObject) root = access_fixture("office", "ready", TRUE);
    json_object_set_boolean_member(object_member(root, "recovery"), "can_restore", FALSE);
    g_assert_true(show_access(&test_app, root));
    gtk_drop_down_set_selected(test_app.access_preset, 2);
    gtk_drop_down_set_selected(test_app.access_scope, 1);
    gtk_editable_set_text(test_app.access_ports, "9003");
    gtk_editable_set_text(test_app.access_source, "172.24.0.4");
    gtk_editable_set_text(test_app.access_interface, "any");
    gtk_drop_down_set_selected(test_app.access_protocol, 0);
    gtk_drop_down_set_selected(test_app.access_duration, 3);
    update_actions(&test_app);
    g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)));
    g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_restore)));
    g_autoptr(GError) error = NULL;
    g_auto(GStrv) args = access_arguments(&test_app, &error);
    g_assert_no_error(error); g_assert_nonnull(args);
    g_assert_cmpstr(args[2], ==, "office"); g_assert_cmpstr(args[3], ==, "9003");
    g_assert_cmpstr(args[4], ==, "tcp"); g_assert_cmpstr(args[5], ==, "172.24.0.4");
    g_assert_cmpstr(args[6], ==, "any"); g_assert_cmpstr(args[7], ==, "0");
}

'''
s = replace(s, 'int main(int argc, char **argv)\n{', tests + 'int main(int argc, char **argv)\n{')
s = replace(s, '    int result = g_test_run();', '''    g_test_add_func("/ui/refresh/navigation-inflight-manual-failure-and-session", test_refresh_navigation_and_failures);
    g_test_add_func("/ui/refresh/resource-invalidation-metadata", test_refresh_resource_metadata);
    g_test_add_func("/ui/refresh/verified-access-without-original-restore", test_verified_access_without_original_restore);
    int result = g_test_run();''')
path.write_text(s)
assert 'Until I revoke it' in Path('src/ui/octoshield-gtk.c').read_text()
subprocess.run(['bash', 'scripts/version.sh', '--check', 'v1.3.4'], check=True)
print('Applied source, native regression and 1.3.4 metadata changes.')
