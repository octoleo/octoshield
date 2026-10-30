/* SPDX-License-Identifier: Apache-2.0 */
/* A separate test executable exercises the real frontend with a harmless
 * fixture child. Production cannot override the helper or bypass its root
 * guard. No system policy, password dialog, or privileged helper is invoked. */
#define main octoshield_application_entry
#include "../src/ui/octoshield-gtk.c"
#undef main

#include <stdio.h>
#include <stdlib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

static App test_app;
static gchar *test_executable;

static void access_fixture_recovery(JsonObject *root, const char *reason, gboolean ready)
{
    const char *profile = string_member(root, "profile", "home");
    json_object_set_string_member(root, "assigned_profile", g_str_equal(reason, "unmanaged") ? "unmanaged" : profile);
    json_object_set_boolean_member(root, "managed", !g_str_equal(reason, "unmanaged"));
    json_object_set_boolean_member(root, "ready", ready);
    JsonObject *recovery = json_object_new();
    json_object_set_string_member(recovery, "reason", reason);
    json_object_set_string_member(recovery, "last_result", ready ? "applied" : "failed");
    json_object_set_string_member(recovery, "message", ready ? "Selected firewall verified." : "Requested profile change failed: fixture nftables reload was refused.");
    json_object_set_string_member(recovery, "transaction", "20261025T120000Z-1234");
    json_object_set_boolean_member(recovery, "can_apply", !g_str_equal(reason, "drift"));
    json_object_set_boolean_member(recovery, "can_restore", !g_str_equal(reason, "unmanaged") && !g_str_equal(reason, "drift"));
    json_object_set_boolean_member(recovery, "can_reconcile", g_str_equal(reason, "drift"));
    JsonObject *observed = json_object_new();
    json_object_set_string_member(observed, "state", ready ? "active" : "partial");
    json_object_set_string_member(observed, "summary", ready ? "The selected native firewall policy is verified." : "Native policy differs from the selected profile.");
    json_object_set_object_member(recovery, "observed", observed);
    json_object_set_object_member(root, "recovery", recovery);
}

static JsonObject *access_fixture(const char *profile, const char *reason, gboolean ready)
{
    JsonObject *root = json_object_new();
    json_object_set_string_member(root, "kind", "access");
    json_object_set_string_member(root, "profile", profile);
    json_object_set_string_member(root, "summary", "Fixture permissions; no host changes.");
    json_object_set_array_member(root, "rules", json_array_new());
    access_fixture_recovery(root, reason, ready);
    return root;
}

static void select_access_profile(const char *profile)
{
    for (guint i = 0; i < test_app.profile_ids->len; i++) {
        if (g_str_equal(g_ptr_array_index(test_app.profile_ids, i), profile)) {
            gtk_drop_down_set_selected(test_app.access_profile, i);
            return;
        }
    }
    g_assert_not_reached();
}

static void ready_access_fixture(void)
{
    select_access_profile("home");
    g_autoptr(JsonObject) root = access_fixture("home", "ready", TRUE);
    g_assert_true(show_access(&test_app, root));
}

static void save_widget_png(GtkWidget *widget, const char *path)
{
    if (g_getenv("OCTOSHIELD_TEST_SCREENSHOTS") == NULL)
        return;
    gint64 deadline = g_get_monotonic_time() + 250 * G_TIME_SPAN_MILLISECOND;
    while (g_get_monotonic_time() < deadline) {
        while (g_main_context_iteration(NULL, FALSE))
            ;
        g_usleep(1000);
    }
    int width = gtk_widget_get_width(widget);
    int height = gtk_widget_get_height(widget);
    g_assert_cmpint(width, >, 0);
    g_assert_cmpint(height, >, 0);
    g_autoptr(GdkPaintable) paintable = gtk_widget_paintable_new(widget);
    GtkSnapshot *snapshot = gtk_snapshot_new();
    gdk_paintable_snapshot(paintable, GDK_SNAPSHOT(snapshot), width, height);
    GskRenderNode *node = gtk_snapshot_free_to_node(snapshot);
    g_assert_nonnull(node);
    GskRenderer *renderer = gtk_native_get_renderer(GTK_NATIVE(widget));
    graphene_rect_t viewport = GRAPHENE_RECT_INIT(0, 0, width, height);
    g_autoptr(GdkTexture) texture = gsk_renderer_render_texture(renderer, node, &viewport);
    g_assert_true(gdk_texture_save_to_png(texture, path));
    gsk_render_node_unref(node);
}

static void fixture_text_event(const char *type, gint64 request, const char *text)
{
    g_autoptr(JsonObject) object = json_object_new();
    json_object_set_string_member(object, "type", type);
    json_object_set_int_member(object, "request", request);
    json_object_set_string_member(object, "text", text);
    g_autoptr(JsonNode) node = json_node_new(JSON_NODE_OBJECT);
    json_node_set_object(node, object);
    g_autoptr(JsonGenerator) generator = json_generator_new();
    json_generator_set_root(generator, node);
    g_autofree gchar *line = json_generator_to_data(generator, NULL);
    puts(line);
}

static int refresh_session_fixture(void)
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

static int fixture(const char *name)
{
    if (g_str_equal(name, "refresh-session")) return refresh_session_fixture();
    if (g_str_equal(name, "access-session")) {
        fputs("{\"type\":\"ready\"}\n", stdout); fflush(stdout);
        char line[8192];
        guint count = 0;
        const char *commands[] = {"recover", "list", "recover", "list", "restore", "list", "reconcile", "list"};
        while (fgets(line, sizeof(line), stdin) != NULL) {
            g_autoptr(JsonParser) parser = json_parser_new();
            if (!json_parser_load_from_data(parser, line, -1, NULL) || count >= G_N_ELEMENTS(commands)) return 20;
            JsonObject *request = json_node_get_object(json_parser_get_root(parser));
            gint64 id = json_object_get_int_member(request, "id");
            JsonArray *args = array_member(request, "args");
            const char *command = commands[count++];
            gboolean restore = g_str_equal(command, "restore");
            if (args == NULL || json_array_get_length(args) != (restore ? 2U : 3U) ||
                g_strcmp0(json_array_get_string_element(args, 0), "access") != 0 ||
                g_strcmp0(json_array_get_string_element(args, 1), command) != 0 ||
                (!restore && g_strcmp0(json_array_get_string_element(args, 2), "office") != 0)) return 21;
            if (g_str_equal(command, "list")) {
                const char *reason = count == 2 ? "incomplete" : count == 4 ? "ready" : count == 6 ? "unmanaged" : "pending";
                g_autoptr(JsonObject) result = access_fixture("office", reason, count == 4 || count == 6);
                g_autoptr(JsonNode) node = json_node_new(JSON_NODE_OBJECT);
                json_node_set_object(node, result);
                g_autoptr(JsonGenerator) generator = json_generator_new();
                json_generator_set_root(generator, node);
                g_autofree gchar *json = json_generator_to_data(generator, NULL);
                fixture_text_event("data", id, json);
            } else {
                g_autofree gchar *review = g_strdup_printf("Exact fixture firewall review: access %s%s. Permission draft is not submitted.", command, restore ? "" : " office");
                fixture_text_event("log", id, review);
                printf("{\"type\":\"confirm\",\"request\":%" G_GINT64_FORMAT ",\"id\":1,\"text\":\"Apply this exact firewall operation?\"}\n", id);
                fflush(stdout);
                if (fgets(line, sizeof(line), stdin) == NULL || !json_parser_load_from_data(parser, line, -1, NULL)) return 22;
                JsonObject *answer = json_node_get_object(json_parser_get_root(parser));
                if (g_strcmp0(string_member(answer, "type", ""), "answer") != 0 ||
                    json_object_get_int_member(answer, "request") != id || json_object_get_int_member(answer, "id") != 1 ||
                    !boolean_member(answer, "allow")) return 23;
            }
            gboolean success = count != 1;
            if (!success) fixture_text_event("stderr", id, "Retained fixture error: nftables reload refused after partial changes.");
            printf("{\"type\":\"done\",\"request\":%" G_GINT64_FORMAT ",\"success\":%s,\"change_started\":true}\n", id, success ? "true" : "false");
            printf("{\"type\":\"finished\",\"request\":%" G_GINT64_FORMAT ",\"exit_code\":%d}\n", id, success ? 0 : 1);
            fflush(stdout);
        }
        return 0;
    }
    if (g_str_equal(name, "session")) {
        fputs("{\"type\":\"ready\"}\n", stdout); fflush(stdout);
        char line[8192];
        guint count = 0;
        while (fgets(line, sizeof(line), stdin) != NULL) {
            g_autoptr(JsonParser) parser = json_parser_new();
            if (!json_parser_load_from_data(parser, line, -1, NULL)) return 10;
            JsonObject *request = json_node_get_object(json_parser_get_root(parser));
            gint64 id = json_object_get_int_member(request, "id");
            JsonArray *args = json_object_get_array_member(request, "args");
            if (args == NULL || json_array_get_length(args) != 1) return 11;
            const char *action = json_array_get_string_element(args, 0);
            count++;
            if (!g_str_equal(action, count == 1 ? "status" : "repair")) return 12;
            printf("{\"type\":\"log\",\"request\":%" G_GINT64_FORMAT ",\"text\":\"same session operation %u\"}\n", id, count);
            if (g_str_equal(action, "repair")) {
                printf("{\"type\":\"log\",\"request\":%" G_GINT64_FORMAT ",\"text\":\"Fixture repair preview: remove the retired /etc/sudoers.d/99-octoshield drop-in.\"}\n", id);
                printf("{\"type\":\"confirm\",\"request\":%" G_GINT64_FORMAT ",\"id\":1,\"text\":\"Apply this exact repair?\"}\n", id);
                fflush(stdout);
                if (fgets(line, sizeof(line), stdin) == NULL || !json_parser_load_from_data(parser, line, -1, NULL)) return 13;
                JsonObject *answer = json_node_get_object(json_parser_get_root(parser));
                if (g_strcmp0(json_object_get_string_member(answer, "type"), "answer") != 0 ||
                    json_object_get_int_member(answer, "request") != id ||
                    json_object_get_int_member(answer, "id") != 1 ||
                    !json_object_get_boolean_member(answer, "allow")) return 14;
            }
            printf("{\"type\":\"done\",\"request\":%" G_GINT64_FORMAT ",\"success\":true}\n", id);
            printf("{\"type\":\"stderr\",\"request\":%" G_GINT64_FORMAT ",\"text\":\"late diagnostic after done\"}\n", id);
            printf("{\"type\":\"finished\",\"request\":%" G_GINT64_FORMAT ",\"exit_code\":0}\n", id);
            fflush(stdout);
        }
        return 0;
    }
    if (g_str_equal(name, "oversize")) {
        for (guint i = 0; i < MAX_PROTOCOL_LINE + 10; i++)
            fputc('x', stdout);
        fputc('\n', stdout);
        fputs("{\"type\":\"done\",\"success\":true}\n", stdout);
        return 0;
    }
    fputs("{\"type\":\"log\",\"text\":\"fixture inspection output\"}\n", stdout);
    fputs("fixture stderr diagnostic\n", stderr);
    if (g_str_has_prefix(name, "failure-")) {
        const gchar *state = g_str_equal(name, "failure-before-change") ? ",\"change_started\":false" :
                             g_str_equal(name, "failure-after-change") ? ",\"change_started\":true" :
                             g_str_equal(name, "failure-invalid-state") ? ",\"change_started\":\"false\"" :
                             g_str_equal(name, "failure-invalid-after-done") ? ",\"change_started\":false" : "";
        printf("{\"type\":\"done\",\"success\":false%s}\n", state);
        if (g_str_equal(name, "failure-invalid-after-done"))
            fputs("{\"type\":\"log\",\"text\":\"unexpected event after completion\"}\n", stdout);
        return 1;
    }
    if (g_str_equal(name, "prompts")) {
        fputs("{\"type\":\"log\",\"text\":\"allow id 1234:5678 name <untrusted device>\\nblock all other devices\"}\n", stdout);
        fputs("{\"type\":\"confirm\",\"id\":1,\"text\":\"Review these exact device rules?\"}\n", stdout);
        fflush(stdout);
        char answer[40];
        if (fgets(answer, sizeof(answer), stdin) == NULL || strcmp(answer, "1 yes\n") != 0)
            return 8;
        fputs("{\"type\":\"confirm\",\"id\":2,\"text\":\"Apply the already reviewed fixture?\"}\n", stdout);
        fflush(stdout);
        if (fgets(answer, sizeof(answer), stdin) == NULL || strcmp(answer, "2 yes\n") != 0)
            return 9;
    }
    if (!g_str_equal(name, "missing-done"))
        fputs("{\"type\":\"done\",\"success\":true}\n", stdout);
    return g_str_equal(name, "bad-exit") ? 7 : 0;
}

static gchar *log_text(void)
{
    GtkTextIter start;
    GtkTextIter end;
    gtk_text_buffer_get_bounds(test_app.log, &start, &end);
    return gtk_text_buffer_get_text(test_app.log, &start, &end, FALSE);
}

static void launch_fixture(const char *name)
{
    g_assert_null(test_app.operation);
    Request *request = g_new0(Request, 1);
    request->app = &test_app;
    request->title = g_strdup("Harmless frontend test");
    request->argv = g_new0(gchar *, 4);
    request->argv[0] = g_strdup(test_executable);
    request->argv[1] = g_strdup("--fixture");
    request->argv[2] = g_strdup(name);
    launch_request(request);
    g_assert_nonnull(test_app.operation);
}

static void drain_operation(gboolean approve)
{
    gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
    guint decisions = 0;
    while (test_app.operation != NULL && g_get_monotonic_time() < deadline) {
        while (g_main_context_iteration(NULL, FALSE))
            ;
        if (approve && test_app.confirmation != NULL) {
            if (decisions == 0) {
                GtkWidget *scroll = adw_message_dialog_get_extra_child(test_app.confirmation);
                GtkWidget *view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));
                GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
                GtkTextIter start;
                GtkTextIter end;
                gtk_text_buffer_get_bounds(buffer, &start, &end);
                g_autofree gchar *review = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
                g_assert_nonnull(strstr(review, "allow id 1234:5678 name <untrusted device>"));
                g_assert_nonnull(strstr(review, "block all other devices"));
                save_widget_png(GTK_WIDGET(test_app.confirmation), "build/ui-confirmation.png");
            }
            decisions++;
            adw_message_dialog_response(test_app.confirmation, "accept");
        }
        g_usleep(1000);
    }
    g_assert_null(test_app.operation);
    if (approve)
        g_assert_cmpuint(decisions, ==, 2);
}

static void test_window(void)
{
    g_assert_true(gtk_widget_get_visible(GTK_WIDGET(test_app.window)));
    GtkSelectionModel *pages = gtk_stack_get_pages(test_app.pages);
    g_assert_cmpuint(g_list_model_get_n_items(G_LIST_MODEL(pages)), ==, 8);
    g_object_unref(pages);
    g_assert_cmpuint(test_app.operation_widgets->len, >, 25);
    save_widget_png(GTK_WIDGET(test_app.window), "build/ui-overview.png");
}

static gboolean widget_has_label_text(GtkWidget *widget, const char *text)
{
    if (GTK_IS_LABEL(widget) && g_str_equal(gtk_label_get_text(GTK_LABEL(widget)), text))
        return TRUE;
    for (GtkWidget *child = gtk_widget_get_first_child(widget); child != NULL; child = gtk_widget_get_next_sibling(child))
        if (widget_has_label_text(child, text)) return TRUE;
    return FALSE;
}

static void test_group_text_escaping(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    g_object_ref_sink(page);
    GtkWidget *group = group_new(page, "Access & <permissions>", "Keep <device> approvals & settings literal.");
    /* Adwaita versions differ in whether property getters retain markup or
     * return rendered text. Check what the actual labels display instead. */
    g_assert_true(widget_has_label_text(group, "Access & <permissions>"));
    g_assert_true(widget_has_label_text(group, "Keep <device> approvals & settings literal."));
    g_object_unref(page);
}

static void test_observed_status_and_overrides(void)
{
    g_autoptr(JsonParser) parser = json_parser_new();
    g_autofree gchar *snapshot = g_strdup_printf(
        "{\"schema\":1,\"checked_at\":%" G_GINT64_FORMAT ","
        "\"profiles\":{\"active\":\"conference\",\"assignments\":{\"firewall\":\"conference\",\"usb\":\"office\"},"
        "\"overrides\":{\"usb\":\"office\"},\"results\":{\"firewall\":{\"status\":\"failed\"}}},"
        "\"controls\":{\"firewall\":{\"state\":\"active\",\"summary\":\"Native firewall is enabled\"},"
        "\"usb\":{\"state\":\"active\",\"summary\":\"Authorization verified\"}},"
        "\"usb\":{\"available\":true,\"pending\":2,\"devices\":[{\"id\":17,\"state\":\"blocked\",\"label\":\"USB device\"}]}}",
        g_get_real_time() / G_USEC_PER_SEC);
    g_assert_true(json_parser_load_from_data(parser, snapshot, -1, NULL));
    render_status(&test_app, json_node_get_object(json_parser_get_root(parser)));
    g_assert_true(test_app.cache_valid);
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.overview_title), "individual overrides"));
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.overview_title), "changes incomplete"));
    StatusRow *firewall = g_ptr_array_index(test_app.status_rows, 0);
    StatusRow *usb = g_ptr_array_index(test_app.status_rows, 1);
    g_assert_cmpstr(gtk_label_get_text(firewall->badge), ==, "Needs attention");
    g_assert_cmpstr(gtk_button_get_label(firewall->review), ==, "Review & recover");
    g_assert_cmpstr(gtk_label_get_text(usb->badge), ==, "Active");
    g_assert_nonnull(strstr(adw_action_row_get_subtitle(usb->row), "office (override)"));
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.usb_pending), "2 blocked devices"));
    g_assert_null(test_app.operation);
    g_assert_null(test_app.preview);
    JsonObject *root = json_node_get_object(json_parser_get_root(parser));
    json_object_set_boolean_member(object_member(root, "profiles"), "available", FALSE);
    render_status(&test_app, root);
    g_assert_cmpstr(gtk_label_get_text(usb->badge), ==, "Unknown");
    g_assert_cmpstr(gtk_label_get_text(firewall->badge), ==, "Unknown");
    /* Losing a fresh observation must clear previous positive indicators. */
    render_status(&test_app, NULL);
    g_assert_false(test_app.cache_valid);
    g_assert_cmpstr(gtk_label_get_text(usb->badge), ==, "Unknown");
    g_assert_cmpstr(gtk_label_get_text(firewall->badge), ==, "Unknown");
}

static void test_profile_catalog_selection(void)
{
    gtk_drop_down_set_selected(test_app.global_profile, 2);
    g_assert_cmpstr(selected_profile(&test_app, test_app.global_profile), ==, "office");
    g_autoptr(JsonParser) parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, "[{\"id\":\"conference\",\"name\":\"Conference\"},{\"id\":\"client-visit\",\"name\":\"Client visit\"},{\"id\":\"home\",\"name\":\"Home\"},{\"id\":\"office\",\"name\":\"Office\"},{\"id\":\"public\",\"name\":\"Public\"}]", -1, NULL));
    update_catalog(&test_app, json_node_get_array(json_parser_get_root(parser)));
    g_assert_cmpuint(test_app.profile_ids->len, ==, 5);
    g_assert_cmpstr(selected_profile(&test_app, test_app.global_profile), ==, "office");
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.global_profile), ==, 3);
    g_assert_true(json_parser_load_from_data(parser, "[{\"id\":\"../escape\",\"name\":\"Invalid\"}]", -1, NULL));
    update_catalog(&test_app, json_node_get_array(json_parser_get_root(parser)));
    g_assert_cmpuint(test_app.profile_ids->len, ==, 5);
}

static void test_repair_status_and_removed_control(void)
{
    for (gsize i = 0; i < G_N_ELEMENTS(actions); i++) g_assert_cmpstr(actions[i].id, !=, "sudo");
    const Action *action = find_action("repair");
    g_assert_nonnull(action);
    g_assert_true(action->privileged);
    g_assert_true(action->changes);
    StatusRow *repair_row = NULL;
    for (guint i = 0; i < test_app.status_rows->len; i++) {
        StatusRow *row = g_ptr_array_index(test_app.status_rows, i);
        g_assert_false(g_str_equal(row->section, "controls") && g_str_equal(row->key, "sudo"));
        if (g_str_equal(row->section, "recovery") && g_str_equal(row->key, "repairs")) repair_row = row;
    }
    g_assert_nonnull(repair_row);
    g_assert_true(widget_has_label_text(gtk_stack_get_child_by_name(test_app.pages, "recovery"), "Repair system"));
    g_autoptr(JsonParser) parser = json_parser_new();
    g_autofree gchar *snapshot = g_strdup_printf("{\"schema\":1,\"checked_at\":%" G_GINT64_FORMAT ",\"controls\":{\"firewall\":{\"state\":\"active\",\"summary\":\"Firewall remains inspected\"}}}", g_get_real_time() / G_USEC_PER_SEC);
    g_assert_true(json_parser_load_from_data(parser, snapshot, -1, NULL));
    JsonObject *root = json_node_get_object(json_parser_get_root(parser));
    render_status(&test_app, root);
    g_assert_true(test_app.cache_valid);
    g_assert_cmpstr(gtk_label_get_text(repair_row->badge), ==, "Needs review");
    g_assert_nonnull(strstr(adw_action_row_get_subtitle(repair_row->row), "Select Repair system"));
    JsonObject *recovery = json_object_new();
    JsonObject *repairs = json_object_new();
    json_object_set_object_member(root, "recovery", recovery);
    json_object_set_object_member(recovery, "repairs", repairs);
    const struct { const char *state; const char *badge; } cases[] = {
        {"active", "Up to date"}, {"partial", "Repair available"}, {"unknown", "Needs review"}
    };
    for (gsize i = 0; i < G_N_ELEMENTS(cases); i++) {
        json_object_set_string_member(repairs, "state", cases[i].state);
        json_object_set_string_member(repairs, "summary", "Inspect <retired> settings & recovery evidence.");
        render_status(&test_app, root);
        g_assert_cmpstr(gtk_label_get_text(repair_row->badge), ==, cases[i].badge);
        g_assert_cmpstr(adw_action_row_get_subtitle(repair_row->row), ==, "Inspect <retired> settings & recovery evidence.");
        g_assert_false(adw_preferences_row_get_use_markup(ADW_PREFERENCES_ROW(repair_row->row)));
    }
    json_object_set_string_member(repairs, "state", "active");
    json_object_set_int_member(repairs, "summary", 10);
    render_status(&test_app, root);
    g_assert_cmpstr(gtk_label_get_text(repair_row->badge), ==, "Needs review");
    g_assert_nonnull(strstr(adw_action_row_get_subtitle(repair_row->row), "Select Repair system"));
    json_object_set_string_member(repairs, "state", "complete");
    json_object_set_string_member(repairs, "summary", "Invalid state must not claim success.");
    render_status(&test_app, root);
    g_assert_cmpstr(gtk_label_get_text(repair_row->badge), ==, "Needs review");
    render_status(&test_app, NULL);
    g_assert_cmpstr(gtk_label_get_text(repair_row->badge), ==, "Needs review");
    g_assert_null(test_app.operation);
}

static void test_data_models(void)
{
    Operation operation = {.app = &test_app, .title = "Refresh device list"};
    test_app.operation = &operation;
    handle_data_log(&test_app, "[{\"id\":22,\"state\":\"blocked\",\"name\":\"<b>untrusted keyboard</b>\"},{\"id\":0,\"name\":\"invalid\"}]");
    g_assert_cmpuint(test_app.usb_inventory_rows->len, ==, 1);
    UsbDevice *device = g_ptr_array_index(test_app.usb_inventory_rows, 0);
    g_assert_cmpstr(device->id, ==, "22");
    g_assert_cmpstr(device->name, ==, "<b>untrusted keyboard</b>");
    operation.title = "Check for OctoShield updates";
    handle_data_log(&test_app, "{\"current\":\"1.1.0\",\"latest\":\"1.2.0\",\"message\":\"Update available\",\"download_url\":\"https://evil.invalid/package.deb\"}");
    g_assert_cmpstr(gtk_link_button_get_uri(test_app.update_link), ==, "https://github.com/octoleo/octoshield/releases/latest");
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.update_status), "1.2.0"));
    /* Unrelated device/log output must never alter update controls. */
    operation.title = "Apply profile";
    handle_data_log(&test_app, "{\"current\":\"fake\",\"latest\":\"fake\",\"message\":\"fake\"}");
    g_assert_null(strstr(gtk_label_get_text(test_app.update_status), "fake"));
    test_app.operation = NULL;
    test_app.usb_inventory = FALSE;
    render_status(&test_app, NULL);
    update_actions(&test_app);
}

static void test_profile_choice_freshness(void)
{
    for (guint i = 0; i < test_app.profile_ids->len; i++)
        if (g_str_equal(g_ptr_array_index(test_app.profile_ids, i), "home")) gtk_drop_down_set_selected(test_app.edit_profile, i);
    GtkDropDown *automatic = g_hash_table_lookup(test_app.setting_choices, "network.autoconnect");
    GtkDropDown *ssh = g_hash_table_lookup(test_app.setting_choices, "services.ssh");
    Operation operation = {.app = &test_app, .title = "Inspect profile configuration"};
    test_app.operation = &operation;
    const char *known = "{\"id\":\"home\",\"network\":{\"autoconnect\":true},\"services\":{\"ssh\":\"enabled\"}}";
    handle_data_log(&test_app, known);
    g_assert_cmpuint(gtk_drop_down_get_selected(automatic), ==, 0);
    g_assert_cmpuint(gtk_drop_down_get_selected(ssh), ==, 0);
    handle_data_log(&test_app, "{\"id\":\"home\"}");
    g_assert_cmpuint(gtk_drop_down_get_selected(automatic), ==, 2);
    g_assert_cmpuint(gtk_drop_down_get_selected(ssh), ==, 3);
    handle_data_log(&test_app, known);
    test_app.operation = NULL;
    for (guint i = 0; i < test_app.profile_ids->len; i++)
        if (g_str_equal(g_ptr_array_index(test_app.profile_ids, i), "office")) gtk_drop_down_set_selected(test_app.edit_profile, i);
    g_assert_cmpuint(gtk_drop_down_get_selected(automatic), ==, 2);
    g_assert_cmpuint(gtk_drop_down_get_selected(ssh), ==, 3);
    g_assert_null(strstr(gtk_label_get_text(test_app.profile_details), "Saved profile: home"));
    ProfileBinding binding = {.app = &test_app, .command = PROFILE_SET, .profile = test_app.edit_profile, .key = "services.ssh", .choice = ssh};
    profile_clicked(NULL, &binding);
    g_assert_null(test_app.preview); g_assert_null(test_app.operation);
    binding.key = "network.autoconnect"; binding.choice = automatic;
    profile_clicked(NULL, &binding);
    g_assert_null(test_app.preview); g_assert_null(test_app.operation);
    update_actions(&test_app);
}

static void receive_data_chunks(Operation *operation, const char *json)
{
    Reader reader = {operation, NULL, g_byte_array_new(), TRUE, FALSE, FALSE};
    for (gsize offset = 0; offset < strlen(json); offset += 4096) {
        g_autofree gchar *chunk = g_strndup(json + offset, MIN((gsize)4096, strlen(json) - offset));
        g_autoptr(JsonBuilder) builder = json_builder_new();
        json_builder_begin_object(builder);
        json_builder_set_member_name(builder, "type"); json_builder_add_string_value(builder, "log");
        json_builder_set_member_name(builder, "text"); json_builder_add_string_value(builder, chunk);
        json_builder_end_object(builder);
        g_autoptr(JsonNode) root = json_builder_get_root(builder);
        g_autoptr(JsonGenerator) generator = json_generator_new();
        json_generator_set_root(generator, root);
        g_autofree gchar *event = json_generator_to_data(generator, NULL);
        g_byte_array_set_size(reader.line, 0);
        g_byte_array_append(reader.line, (const guint8 *)event, strlen(event));
        handle_line(&reader);
    }
    g_byte_array_unref(reader.line);
    g_assert_false(operation->data_seen);
    g_assert_cmpstr(operation->data_output->str, ==, json);
    handle_data_log(&test_app, operation->data_output->str);
    g_assert_true(operation->data_seen);
}

static void test_large_data_records(void)
{
    Operation operation = {.app = &test_app, .title = "Inspect profile configuration", .review = g_string_new(NULL), .data_output = g_string_new(NULL)};
    test_app.operation = &operation;
    GString *profile = g_string_new("{\"id\":\"office\",\"name\":\"Office\",\"firewall\":{\"rules\":[");
    for (guint i = 0; i < 80; i++)
        g_string_append_printf(profile, "%s{\"id\":\"r1791830500-123-%u\",\"port\":443,\"protocol\":\"tcp\",\"source\":\"192.168.1.0/24\",\"interface\":\"wlan0\",\"expires_at\":0}", i > 0 ? "," : "", i);
    g_string_append(profile, "]}}");
    g_assert_cmpuint(profile->len, >, 4096);
    receive_data_chunks(&operation, profile->str);
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.profile_details), "Saved firewall exceptions: 80"));
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.profile_details), "r1791830500-123-79"));
    g_string_free(profile, TRUE);
    operation.title = "Refresh device list";
    operation.data_seen = FALSE;
    g_string_truncate(operation.data_output, 0);
    GString *devices = g_string_new("[");
    for (guint i = 0; i < 100; i++)
        g_string_append_printf(devices, "%s{\"id\":%u,\"state\":\"blocked\",\"name\":\"USB device with a keyboard interface\"}", i > 0 ? "," : "", i + 1);
    g_string_append_c(devices, ']');
    g_assert_cmpuint(devices->len, >, 4096);
    receive_data_chunks(&operation, devices->str);
    g_assert_cmpuint(test_app.usb_inventory_rows->len, ==, 100);
    g_string_free(devices, TRUE);
    g_string_free(operation.review, TRUE);
    g_string_free(operation.data_output, TRUE);
    test_app.operation = NULL;
    test_app.usb_inventory = FALSE;
    render_status(&test_app, NULL);
    update_actions(&test_app);
}

static void test_accounts_entry(void)
{
    /* Match the upstream GNOME 46/50 Users desktop entry without launching a
     * password UI or forwarding user-supplied arguments. */
    g_assert_cmpstr(accounts_argv[0], ==, "/usr/bin/gnome-control-center");
    g_assert_cmpstr(accounts_argv[1], ==, "system");
    g_assert_cmpstr(accounts_argv[2], ==, "users");
    g_assert_null(accounts_argv[3]);
}

static void test_brand_resources_and_theme(void)
{
    /* These digests belong to the original user-supplied files. Embedded
     * artwork must retain those exact bytes; scaling happens only in GTK. */
    static const char *const resources[][2] = {
        {BRAND_RESOURCE_LIGHT, "3bd6dd86d7e14f37e9150c3f3d344a714966967da8859a5245fdcf05e0ba1604"},
        {BRAND_RESOURCE_DARK, "ef650804aea968b660c0d27e05d63307caa13470fd9bd7120f4ed71022abbf3e"}
    };
    for (gsize i = 0; i < G_N_ELEMENTS(resources); i++) {
        g_autoptr(GError) error = NULL;
        g_autoptr(GBytes) bytes = g_resources_lookup_data(resources[i][0], G_RESOURCE_LOOKUP_FLAGS_NONE, &error);
        g_assert_no_error(error);
        g_assert_nonnull(bytes);
        g_autofree gchar *checksum = g_compute_checksum_for_bytes(G_CHECKSUM_SHA256, bytes);
        g_assert_cmpstr(checksum, ==, resources[i][1]);
    }
    g_assert_cmpuint(test_app.brand_pictures->len, ==, 2);
    g_assert_cmpint(adw_style_manager_get_color_scheme(test_app.style_manager), ==, ADW_COLOR_SCHEME_DEFAULT);
    adw_style_manager_set_color_scheme(test_app.style_manager, ADW_COLOR_SCHEME_FORCE_LIGHT);
    g_assert_false(adw_style_manager_get_dark(test_app.style_manager));
    g_autoptr(GPtrArray) light_pictures = g_ptr_array_new_with_free_func(g_object_unref);
    for (guint i = 0; i < test_app.brand_pictures->len; i++) {
        GtkPicture *picture = g_ptr_array_index(test_app.brand_pictures, i);
        GdkPaintable *paintable = gtk_picture_get_paintable(picture);
        g_assert_nonnull(paintable);
        g_assert_cmpint(gdk_paintable_get_intrinsic_width(paintable), >, 0);
        g_ptr_array_add(light_pictures, g_object_ref(paintable));
    }
    adw_style_manager_set_color_scheme(test_app.style_manager, ADW_COLOR_SCHEME_FORCE_DARK);
    g_assert_true(adw_style_manager_get_dark(test_app.style_manager));
    for (guint i = 0; i < test_app.brand_pictures->len; i++) {
        GtkPicture *picture = g_ptr_array_index(test_app.brand_pictures, i);
        GdkPaintable *paintable = gtk_picture_get_paintable(picture);
        g_assert_nonnull(paintable);
        g_assert_true(paintable != g_ptr_array_index(light_pictures, i));
    }
    adw_style_manager_set_color_scheme(test_app.style_manager, ADW_COLOR_SCHEME_DEFAULT);
}

static void test_about_identity(void)
{
    GtkWidget *about = about_window(&test_app);
    g_assert_cmpstr(adw_about_window_get_application_name(ADW_ABOUT_WINDOW(about)), ==, "OctoShield");
    g_assert_cmpstr(adw_about_window_get_application_icon(ADW_ABOUT_WINDOW(about)), ==, "io.vdm.OctoShield");
    g_assert_cmpstr(adw_about_window_get_developer_name(ADW_ABOUT_WINDOW(about)), ==, "Vast Development Method");
    g_assert_cmpstr(adw_about_window_get_website(ADW_ABOUT_WINDOW(about)), ==, "https://www.vdm.io");
    g_assert_cmpstr(adw_about_window_get_version(ADW_ABOUT_WINDOW(about)), ==, OCTOSHIELD_VERSION);
    g_assert_nonnull(strstr(adw_about_window_get_comments(ADW_ABOUT_WINDOW(about)), "Octoleo"));
    gtk_window_destroy(GTK_WINDOW(about));
}

static void test_page_screenshots(void)
{
    /* Capture the real initial pages before any fixture process runs. We do
     * not invent inspection output, a protected state, or a device inventory. */
    g_assert_null(test_app.operation);
    g_autofree gchar *initial_log = log_text();
    g_assert_nonnull(strstr(initial_log, "No protection has been applied"));
    static const char *const pages[] = {"overview", "protections", "usb", "office", "privacy", "diagnostics", "monitoring", "recovery"};
    static const AdwColorScheme schemes[] = {ADW_COLOR_SCHEME_FORCE_LIGHT, ADW_COLOR_SCHEME_FORCE_DARK};
    static const char *const labels[] = {"light", "dark"};
    if (g_getenv("OCTOSHIELD_TEST_SCREENSHOTS") != NULL)
        g_assert_cmpint(g_mkdir_with_parents("build/screenshots", 0755), ==, 0);
    for (gsize theme = 0; theme < G_N_ELEMENTS(schemes); theme++) {
        adw_style_manager_set_color_scheme(test_app.style_manager, schemes[theme]);
        for (gsize i = 0; i < G_N_ELEMENTS(pages); i++) {
            GtkListBoxRow *row = gtk_list_box_get_row_at_index(test_app.navigation, (int)i);
            gtk_list_box_select_row(test_app.navigation, row);
            g_assert_cmpstr(gtk_stack_get_visible_child_name(test_app.pages), ==, pages[i]);
            g_autofree gchar *path = g_strdup_printf("build/screenshots/OctoShield-%s-%s.png", pages[i], labels[theme]);
            save_widget_png(GTK_WIDGET(test_app.window), path);
        }
    }
    gtk_list_box_select_row(test_app.navigation, gtk_list_box_get_row_at_index(test_app.navigation, 0));
    adw_style_manager_set_color_scheme(test_app.style_manager, ADW_COLOR_SCHEME_DEFAULT);
}

static void test_icon_decoding(void)
{
    /* Theme lookup alone can succeed without an SVG loader, while GTK renders
     * a broken-image placeholder. Decode the actual backing file for every
     * symbolic icon the frontend uses, including the monitoring activity icon.
     * These names deliberately come from Adwaita, not optional application
     * packages such as GNOME System Monitor. */
    static const char *const names[] = {
        "dialog-information-symbolic", "dialog-password-symbolic",
        "dialog-question-symbolic", "dialog-warning-symbolic", "object-select-symbolic",
        "document-open-recent-symbolic", "drive-removable-media-symbolic",
        "edit-undo-symbolic", "help-browser-symbolic", "help-about-symbolic",
        "media-playback-stop-symbolic", "network-wireless-symbolic",
        "network-workgroup-symbolic", "network-transmit-receive-symbolic",
        "notifications-disabled-symbolic", "preferences-system-notifications-symbolic",
        "preferences-system-symbolic", "security-high-symbolic",
        "software-update-available-symbolic", "system-lock-screen-symbolic",
        "text-x-generic-symbolic", "view-grid-symbolic", "view-refresh-symbolic"
    };
    GtkIconTheme *theme = gtk_icon_theme_get_for_display(gtk_widget_get_display(GTK_WIDGET(test_app.window)));
    for (gsize i = 0; i < G_N_ELEMENTS(names); i++) {
        g_test_message("Decoding installed icon %s", names[i]);
        g_autoptr(GtkIconPaintable) icon = gtk_icon_theme_lookup_icon(theme, names[i], NULL,
                                                                   32, 1, GTK_TEXT_DIR_LTR,
                                                                   GTK_ICON_LOOKUP_FORCE_SYMBOLIC);
        g_assert_nonnull(icon);
        g_assert_cmpstr(gtk_icon_paintable_get_icon_name(icon), ==, names[i]);
        GFile *file = gtk_icon_paintable_get_file(icon);
        g_assert_nonnull(file);
        g_autoptr(GError) error = NULL;
        g_autoptr(GFileInputStream) input = g_file_read(file, NULL, &error);
        g_assert_no_error(error);
        g_assert_nonnull(input);
        g_autoptr(GdkPixbuf) pixbuf = gdk_pixbuf_new_from_stream_at_scale(G_INPUT_STREAM(input),
                                                                      32, 32, TRUE, NULL, &error);
        g_assert_no_error(error);
        g_assert_nonnull(pixbuf);
        g_assert_cmpint(gdk_pixbuf_get_width(pixbuf), >, 0);
        g_assert_cmpint(gdk_pixbuf_get_height(pixbuf), >, 0);
    }
}

static void test_success(void)
{
    launch_fixture("success");
    drain_operation(FALSE);
    g_autofree gchar *text = log_text();
    g_assert_nonnull(strstr(text, "fixture inspection output"));
    g_assert_nonnull(strstr(text, "fixture stderr diagnostic"));
    g_assert_nonnull(strstr(text, "Operation completed successfully."));
}

static void test_missing_done(void)
{
    launch_fixture("missing-done");
    drain_operation(FALSE);
    g_autofree gchar *text = log_text();
    g_assert_nonnull(strstr(text, "No valid completion result"));
    g_assert_null(strstr(text, "Operation completed successfully."));
}

static void test_exit_mismatch(void)
{
    launch_fixture("bad-exit");
    drain_operation(FALSE);
    g_autofree gchar *text = log_text();
    g_assert_nonnull(strstr(text, "Operation declined or failed."));
    g_assert_null(strstr(text, "Operation completed successfully."));
}

static void test_oversize(void)
{
    launch_fixture("oversize");
    drain_operation(FALSE);
    g_autofree gchar *text = log_text();
    g_assert_nonnull(strstr(text, "exceeded the allowed line length"));
    g_assert_null(strstr(text, "Operation completed successfully."));
    g_assert_cmpuint(strlen(text), <, 5000);
}

static void test_failure_change_state(void)
{
    const struct { const gchar *fixture; gboolean unchanged; } cases[] = {
        {"failure-before-change", TRUE},
        {"failure-after-change", FALSE},
        {"failure-unknown-state", FALSE},
        {"failure-invalid-state", FALSE},
        {"failure-invalid-after-done", FALSE}
    };
    for (guint i = 0; i < G_N_ELEMENTS(cases); i++) {
        g_test_message("Failure feedback for %s", cases[i].fixture);
        launch_fixture(cases[i].fixture);
        drain_operation(FALSE);
        g_autofree gchar *text = log_text();
        g_assert_null(strstr(text, "Operation completed successfully."));
        if (cases[i].unchanged) {
            g_assert_nonnull(strstr(text, "No protection changes were started."));
            g_assert_null(strstr(text, "Earlier confirmed changes may still be in effect"));
            g_assert_cmpstr(gtk_label_get_text(test_app.activity), ==,
                            "Operation did not start — review the details");
        } else {
            g_assert_null(strstr(text, "No protection changes were started."));
            g_assert_nonnull(strstr(text, "Earlier confirmed changes may still be in effect"));
        }
    }
}

static void test_confirmations(void)
{
    launch_fixture("prompts");
    drain_operation(TRUE);
    g_autofree gchar *text = log_text();
    g_assert_nonnull(strstr(text, "Operation completed successfully."));
}


static JsonObject *usb_fixture(const char *token, const char *profile, const char *state)
{
    JsonObject *usb = json_object_new();
    json_object_set_boolean_member(usb, "available", TRUE);
    json_object_set_int_member(usb, "pending", g_str_equal(state, "blocked") ? 1 : 0);
    json_object_set_string_member(usb, "profile", profile);
    JsonArray *devices = json_array_new();
    JsonObject *device = json_object_new();
    json_object_set_int_member(device, "id", 42);
    json_object_set_string_member(device, "token", token);
    json_object_set_string_member(device, "profile", profile);
    json_object_set_string_member(device, "state", state);
    json_object_set_string_member(device, "name", "Travel USB key <untrusted name>");
    json_object_set_string_member(device, "vendor_product", "1234:5678");
    json_object_set_string_member(device, "port", "1-2");
    json_object_set_string_member(device, "category", "Storage");
    json_array_add_object_element(devices, device);
    json_object_set_array_member(usb, "devices", devices);
    return usb;
}

static void test_usb_prompt_deduplication_and_cancel(void)
{
    g_autofree gchar *token = g_strnfill(64, 'a');
    g_autofree gchar *replacement = g_strnfill(64, 'b');
    g_autoptr(JsonObject) usb = usb_fixture(token, "office", "blocked");
    test_app.local_session_ready = FALSE;
    render_usb_status(&test_app, usb);
    g_assert_null(test_app.usb_prompt);
    test_app.local_session_ready = TRUE;
    render_usb_status(&test_app, usb);
    g_assert_nonnull(test_app.usb_prompt);
    g_assert_cmpstr(adw_message_dialog_get_default_response(test_app.usb_prompt), ==, "block");
    g_assert_cmpstr(adw_message_dialog_get_close_response(test_app.usb_prompt), ==, "block");
    g_assert_nonnull(strstr(adw_message_dialog_get_body(test_app.usb_prompt), "office"));
    save_widget_png(GTK_WIDGET(test_app.usb_prompt), "build/ui-usb-approval.png");
    adw_message_dialog_response(test_app.usb_prompt, "block");
    g_assert_null(test_app.operation);
    g_assert_null(test_app.pending_request);
    g_assert_null(test_app.session);
    render_usb_status(&test_app, usb);
    g_assert_null(test_app.usb_prompt);
    json_object_set_string_member(json_array_get_object_element(array_member(usb, "devices"), 0), "token", replacement);
    render_usb_status(&test_app, usb);
    g_assert_nonnull(test_app.usb_prompt);
    /* Disconnecting revokes the visible decision without submitting approval. */
    render_usb_status(&test_app, NULL);
    g_assert_null(test_app.usb_prompt);
    g_assert_null(test_app.operation);
    g_assert_null(test_app.pending_request);
    test_app.local_session_ready = FALSE;
}

static void test_usb_approval_is_bound_before_authentication(void)
{
    g_autofree gchar *token = g_strnfill(64, 'c');
    g_autoptr(JsonObject) usb = usb_fixture(token, "conference", "blocked");
    test_app.local_session_ready = TRUE;
    render_usb_status(&test_app, usb);
    g_assert_nonnull(test_app.usb_prompt);
    /* An in-progress synthetic authentication holds the request without ever
     * spawning pkexec or accepting a system credential in this test. */
    Session session = {.app = &test_app};
    test_app.auth_required = TRUE;
    test_app.session = &session;
    adw_message_dialog_response(test_app.usb_prompt, "profile");
    g_assert_nonnull(test_app.pending_request);
    g_assert_cmpstr(test_app.pending_request->argv[2], ==, "usb");
    g_assert_cmpstr(test_app.pending_request->argv[3], ==, "approve");
    g_assert_cmpstr(test_app.pending_request->argv[4], ==, "42");
    g_assert_cmpstr(test_app.pending_request->argv[5], ==, token);
    g_assert_cmpstr(test_app.pending_request->argv[6], ==, "conference");
    g_assert_cmpstr(test_app.pending_request->argv[7], ==, "profile");
    g_assert_null(test_app.operation);
    request_free(test_app.pending_request); test_app.pending_request = NULL;
    test_app.session = NULL; test_app.auth_required = FALSE;
    test_app.local_session_ready = FALSE;
    render_usb_status(&test_app, NULL);
    update_actions(&test_app);
}

static void test_usb_profile_and_remembered_decisions(void)
{
    g_autofree gchar *token = g_strnfill(64, 'd');
    g_autoptr(JsonObject) usb = usb_fixture(token, "office", "blocked");
    JsonObject *device = json_array_get_object_element(array_member(usb, "devices"), 0);
    json_object_set_boolean_member(device, "remembered", TRUE);
    json_object_set_string_member(device, "name", "");
    json_object_set_string_member(device, "label", "USB device");
    test_app.local_session_ready = TRUE;
    render_usb_status(&test_app, usb);
    g_assert_nonnull(test_app.usb_prompt);
    g_assert_nonnull(strstr(adw_message_dialog_get_body(test_app.usb_prompt), "USB device"));
    g_assert_cmpstr(adw_message_dialog_get_response_label(test_app.usb_prompt, "once"), ==, "Allow now");
    g_assert_false(adw_message_dialog_get_response_enabled(test_app.usb_prompt, "profile"));
    adw_message_dialog_response(test_app.usb_prompt, "block");
    json_object_set_string_member(usb, "profile", "home");
    json_object_set_string_member(device, "profile", "home");
    json_object_set_boolean_member(device, "remembered", FALSE);
    render_usb_status(&test_app, usb);
    g_assert_nonnull(test_app.usb_prompt);
    g_assert_nonnull(strstr(adw_message_dialog_get_body(test_app.usb_prompt), "home"));
    /* A policy change closes this stale prompt and does not turn Cancel into
     * a block command against a device that is now allowed. */
    json_object_set_string_member(device, "state", "allowed");
    render_usb_status(&test_app, usb);
    g_assert_null(test_app.usb_prompt);
    UsbDevice *allowed = g_ptr_array_index(test_app.usb_inventory_rows, 0);
    show_usb_prompt(allowed);
    g_assert_cmpstr(adw_message_dialog_get_heading(test_app.usb_prompt), ==, "Remember this USB device?");
    g_assert_cmpstr(adw_message_dialog_get_response_label(test_app.usb_prompt, "block"), ==, "Cancel");
    adw_message_dialog_response(test_app.usb_prompt, "block");
    g_assert_null(test_app.operation);
    render_usb_status(&test_app, NULL);
    test_app.local_session_ready = FALSE;
}

static GVariant *login_fixture(gboolean active, gboolean remote, gboolean locked, const char *type, guint uid)
{
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&builder, "{sv}", "Active", g_variant_new_boolean(active));
    g_variant_builder_add(&builder, "{sv}", "Remote", g_variant_new_boolean(remote));
    g_variant_builder_add(&builder, "{sv}", "LockedHint", g_variant_new_boolean(locked));
    g_variant_builder_add(&builder, "{sv}", "Type", g_variant_new_string(type));
    g_variant_builder_add(&builder, "{sv}", "User", g_variant_new("(uo)", uid, "/org/freedesktop/login1/user/test"));
    return g_variant_ref_sink(g_variant_builder_end(&builder));
}

static void test_login_requires_local_unlocked_graphical_owner(void)
{
    g_autoptr(GVariant) eligible = login_fixture(TRUE, FALSE, FALSE, "wayland", getuid());
    g_autoptr(GVariant) locked = login_fixture(TRUE, FALSE, TRUE, "wayland", getuid());
    g_autoptr(GVariant) remote = login_fixture(TRUE, TRUE, FALSE, "x11", getuid());
    g_autoptr(GVariant) inactive = login_fixture(FALSE, FALSE, FALSE, "wayland", getuid());
    g_autoptr(GVariant) tty = login_fixture(TRUE, FALSE, FALSE, "tty", getuid());
    g_autoptr(GVariant) other = login_fixture(TRUE, FALSE, FALSE, "wayland", getuid() + 1);
    g_assert_true(login_properties_eligible(eligible));
    g_assert_false(login_properties_eligible(locked));
    g_assert_false(login_properties_eligible(remote));
    g_assert_false(login_properties_eligible(inactive));
    g_assert_false(login_properties_eligible(tty));
    g_assert_false(login_properties_eligible(other));
}

static void test_session_reuses_authenticated_transport(void)
{
    const char *const argv[] = {test_executable, "--fixture", "session", NULL};
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
    const char *const args[] = {"status"};
    start_action(&test_app, "Session operation one", NULL, TRUE, FALSE, 1, args);
    drain_operation(FALSE);
    g_assert_true(session->ready);
    g_assert_false(g_output_stream_is_closed(session->input));
    Binding repair = {.app = &test_app, .action = find_action("repair")};
    fixed_action_clicked(NULL, &repair);
    deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (test_app.confirmation == NULL && g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
    g_assert_nonnull(test_app.confirmation);
    g_assert_true(test_app.session == session);
    g_assert_null(test_app.preview);
    GtkWidget *scroll = adw_message_dialog_get_extra_child(test_app.confirmation);
    GtkWidget *view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    GtkTextIter review_start, review_end;
    gtk_text_buffer_get_bounds(buffer, &review_start, &review_end);
    g_autofree gchar *review = gtk_text_buffer_get_text(buffer, &review_start, &review_end, FALSE);
    g_assert_nonnull(strstr(review, "remove the retired /etc/sudoers.d/99-octoshield drop-in"));
    g_assert_nonnull(strstr(review, "Apply this exact repair?"));
    adw_message_dialog_response(test_app.confirmation, "accept");
    drain_operation(FALSE);
    g_autofree gchar *text = log_text();
    g_assert_nonnull(strstr(text, "same session operation 2"));
    g_assert_nonnull(strstr(text, "late diagnostic after done"));
    g_assert_nonnull(strstr(text, "Operation completed successfully."));
    g_assert_cmpuint(session->next_request, ==, 2);
    session_revoke(&test_app, "Test lock");
    deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (test_app.session != NULL && g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
    g_assert_null(test_app.session);
    g_assert_false(administrator_ready(&test_app));
    g_assert_cmpstr(gtk_stack_get_visible_child_name(test_app.access_pages), ==, "locked");
    test_app.auth_required = FALSE; test_app.local_session_ready = FALSE;
    update_actions(&test_app);
}

static void test_access_recovery_uses_session_and_retains_failure(void)
{
    select_access_profile("office");
    access_cancel_edit(NULL, &test_app);
    gtk_drop_down_set_selected(test_app.access_preset, 2);
    gtk_drop_down_set_selected(test_app.access_scope, 1);
    gtk_editable_set_text(test_app.access_ports, "8080,8443");
    gtk_editable_set_text(test_app.access_source, "192.168.20.42");
    gtk_editable_set_text(test_app.access_interface, "wlp2s0");
    gtk_drop_down_set_selected(test_app.access_duration, 2);
    g_autoptr(JsonObject) initial = access_fixture("office", "incomplete", FALSE);
    g_assert_true(show_access(&test_app, initial));
    const char *const argv[] = {test_executable, "--fixture", "access-session", NULL};
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
    GtkButton *buttons[] = {test_app.access_apply, test_app.access_apply, test_app.access_restore, test_app.access_reconcile};
    const char *reviews[] = {"access recover office", "access recover office", "access restore", "access reconcile office"};
    for (guint i = 0; i < G_N_ELEMENTS(buttons); i++) {
        if (i == 3) {
            access_fixture_recovery(initial, "drift", FALSE);
            g_assert_true(show_access(&test_app, initial));
        }
        g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(buttons[i])));
        g_signal_emit_by_name(buttons[i], "clicked");
        deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
        while (test_app.confirmation == NULL && g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
        g_assert_nonnull(test_app.confirmation);
        g_assert_true(test_app.session == session);
        g_assert_null(test_app.preview);
        GtkWidget *scroll = adw_message_dialog_get_extra_child(test_app.confirmation);
        GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll))));
        GtkTextIter start, end;
        gtk_text_buffer_get_bounds(buffer, &start, &end);
        g_autofree gchar *review = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
        g_assert_nonnull(strstr(review, reviews[i]));
        adw_message_dialog_response(test_app.confirmation, "accept");
        deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
        guint64 expected = 2 * (i + 1);
        while ((session->next_request < expected || test_app.operation != NULL || test_app.private_refresh_idle != 0) && g_get_monotonic_time() < deadline) {
            g_main_context_iteration(NULL, FALSE); g_usleep(1000);
        }
        g_assert_null(test_app.operation);
        g_assert_cmpuint(session->next_request, ==, expected);
        g_assert_true(test_app.session == session);
        g_assert_true(session->ready);
        g_assert_true(test_app.access_loaded);
        g_assert_cmpstr(selected_profile(&test_app, test_app.access_profile), ==, "office");
        g_assert_cmpstr(gtk_editable_get_text(test_app.access_ports), ==, "8080,8443");
        g_assert_cmpstr(gtk_editable_get_text(test_app.access_source), ==, "192.168.20.42");
        g_assert_cmpuint(gtk_drop_down_get_selected(test_app.access_duration), ==, 2);
        g_assert_true(gtk_widget_get_visible(GTK_WIDGET(test_app.access_failure)));
        gtk_text_buffer_get_bounds(test_app.access_failure_log, &start, &end);
        g_autofree gchar *failure = gtk_text_buffer_get_text(test_app.access_failure_log, &start, &end, FALSE);
        g_assert_nonnull(strstr(failure, "Retained fixture error: nftables reload refused after partial changes."));
        g_autofree gchar *current_log = log_text();
        if (i == 0) g_assert_nonnull(strstr(current_log, "Retained fixture error"));
        else g_assert_null(strstr(current_log, "Retained fixture error"));
        g_assert_cmpint(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)), ==, i == 1 || i == 2);
    }
    /* Finish GTK dialog and text-scrolling transitions before unmapping the
     * application immediately after these deliberately rapid fixture replies. */
    deadline = g_get_monotonic_time() + 250 * G_TIME_SPAN_MILLISECOND;
    while (g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
    session_revoke(&test_app, "Test recovery lock");
    deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (test_app.session != NULL && g_get_monotonic_time() < deadline) { g_main_context_iteration(NULL, FALSE); g_usleep(1000); }
    g_assert_null(test_app.session);
    test_app.auth_required = FALSE;
    test_app.local_session_ready = FALSE;
    update_actions(&test_app);
}

static void test_guided_access_and_connections(void)
{
    ready_access_fixture();
    g_autoptr(JsonParser) parser = json_parser_new();
    const char *data = "{\"kind\":\"connections\",\"connections\":["
        "{\"uuid\":\"11111111-1111-1111-1111-111111111111\",\"name\":\"Workshop Wi-Fi\",\"type\":\"wifi\",\"interface\":\"wlp2s0\",\"active\":true,\"lan_candidate\":true,\"subnets\":[\"192.168.20.0/24\"],\"autoconnect\":\"no\",\"mdns\":\"0\",\"llmnr\":\"0\",\"mac\":\"stable\",\"runtime\":{\"state\":\"pending\",\"summary\":\"Reconnect to apply the saved privacy settings.\"},\"source_files\":[\"/etc/NetworkManager/system-connections/workshop.nmconnection\"]},"
        "{\"uuid\":\"22222222-2222-2222-2222-222222222222\",\"name\":\"Docker bridge\",\"type\":\"bridge\",\"interface\":\"docker0\",\"active\":true,\"lan_candidate\":false,\"subnets\":[\"172.17.0.0/16\"]}]}";
    g_assert_true(json_parser_load_from_data(parser, data, -1, NULL));
    show_connections(&test_app, json_node_get_object(json_parser_get_root(parser)));
    g_assert_true(test_app.connections_loaded);
    g_assert_cmpuint(test_app.lan_options->len, ==, 1);
    g_assert_cmpstr(string_member(selected_connection(&test_app), "name", ""), ==, "Workshop Wi-Fi");
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.privacy_autoconnect), ==, 1);
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.privacy_discovery), ==, 1);
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.privacy_mac), ==, 0);
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.privacy_source), "workshop.nmconnection"));
    gtk_drop_down_set_selected(test_app.access_preset, 0);
    gtk_drop_down_set_selected(test_app.access_scope, 0);
    gtk_drop_down_set_selected(test_app.access_duration, 1);
    g_autoptr(GError) error = NULL;
    g_auto(GStrv) args = access_arguments(&test_app, &error);
    g_assert_no_error(error); g_assert_nonnull(args);
    g_assert_cmpstr(args[1], ==, "allow");
    g_assert_cmpstr(args[3], ==, "80,443");
    g_assert_cmpstr(args[4], ==, "tcp");
    g_assert_cmpstr(args[5], ==, "192.168.20.0/24");
    g_assert_cmpstr(args[6], ==, "wlp2s0");
    g_assert_cmpstr(args[7], ==, "60");
    g_assert_false(gtk_widget_get_visible(test_app.access_custom));
    g_assert_true(json_parser_load_from_data(parser, "{\"kind\":\"connections\",\"connections\":[]}", -1, NULL));
    g_assert_true(show_connections(&test_app, json_node_get_object(json_parser_get_root(parser))));
    g_assert_cmpuint(test_app.lan_options->len, ==, 0);
    g_auto(GStrv) missing = access_arguments(&test_app, &error);
    g_assert_null(missing); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
    g_assert_true(json_parser_load_from_data(parser, data, -1, NULL));
    g_assert_true(show_connections(&test_app, json_node_get_object(json_parser_get_root(parser))));
    test_app.connections_loaded = FALSE;
    g_auto(GStrv) stale = access_arguments(&test_app, &error);
    g_assert_null(stale); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
    test_app.connections_loaded = TRUE;
    update_actions(&test_app);
    g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)));
    select_page(&test_app, "office");
    save_widget_png(GTK_WIDGET(test_app.window), "build/ui-guided-access.png");
    select_page(&test_app, "privacy");
    save_widget_png(GTK_WIDGET(test_app.window), "build/ui-connection-privacy.png");
}

static void test_ambiguous_network_and_privacy(void)
{
    ready_access_fixture();
    g_clear_pointer(&test_app.lan_options, g_ptr_array_unref);
    g_clear_pointer(&test_app.access_network_identity, g_free);
    g_autoptr(JsonParser) parser = json_parser_new();
    const char *data = "{\"kind\":\"connections\",\"connections\":["
        "{\"uuid\":\"11111111-1111-1111-1111-111111111111\",\"name\":\"Workshop Wi-Fi\",\"type\":\"wifi\",\"interface\":\"wlp2s0\",\"active\":true,\"lan_candidate\":true,\"subnets\":[\"192.168.20.0/24\"],\"autoconnect\":\"unknown\",\"mdns\":\"0\",\"llmnr\":\"2\",\"mac\":\"random\"},"
        "{\"uuid\":\"33333333-3333-3333-3333-333333333333\",\"name\":\"Ethernet\",\"type\":\"ethernet\",\"interface\":\"enp1s0\",\"active\":true,\"lan_candidate\":true,\"subnets\":[\"192.168.30.0/24\"]}]}";
    g_assert_true(json_parser_load_from_data(parser, data, -1, NULL));
    g_assert_true(show_connections(&test_app, json_node_get_object(json_parser_get_root(parser))));
    g_assert_cmpuint(test_app.lan_options->len, ==, 2);
    /* Use a real placeholder: some GTK versions retain an existing choice
     * when asked for GTK_INVALID_LIST_POSITION. */
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.access_network), ==, 2);
    g_autoptr(GError) error = NULL;
    g_auto(GStrv) ambiguous = access_arguments(&test_app, &error);
    g_assert_null(ambiguous); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
    gtk_drop_down_set_selected(test_app.access_network, 1);
    g_auto(GStrv) chosen = access_arguments(&test_app, &error);
    g_assert_no_error(error); g_assert_nonnull(chosen);
    g_assert_cmpstr(chosen[5], ==, "192.168.30.0/24");
    g_assert_cmpstr(chosen[6], ==, "enp1s0");
    g_assert_true(show_connections(&test_app, json_node_get_object(json_parser_get_root(parser))));
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.access_network), ==, 1);
    g_auto(GStrv) preserved = access_arguments(&test_app, &error);
    g_assert_no_error(error); g_assert_nonnull(preserved);
    g_assert_cmpstr(preserved[5], ==, "192.168.30.0/24");
    JsonArray *connections = array_member(json_node_get_object(json_parser_get_root(parser)), "connections");
    JsonNode *first = json_node_copy(json_array_get_element(connections, 0));
    json_array_remove_element(connections, 0);
    json_array_add_element(connections, first);
    g_assert_true(show_connections(&test_app, json_node_get_object(json_parser_get_root(parser))));
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.access_network), ==, 0);
    g_auto(GStrv) reordered = access_arguments(&test_app, &error);
    g_assert_no_error(error); g_assert_nonnull(reordered);
    g_assert_cmpstr(reordered[5], ==, "192.168.30.0/24");
    g_assert_cmpstr(reordered[6], ==, "enp1s0");
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.privacy_autoconnect), ==, 2);
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.privacy_discovery), ==, 2);
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.privacy_mac), ==, 2);
    GtkWidget *save = gtk_button_new();
    g_object_ref_sink(save);
    g_object_set_data(G_OBJECT(save), "privacy-key", "discovery");
    privacy_save_clicked(GTK_BUTTON(save), &test_app);
    g_assert_null(test_app.operation); g_assert_null(test_app.preview);
    GListModel *windows = gtk_window_get_toplevels();
    gboolean refused = FALSE;
    for (guint i = 0; i < g_list_model_get_n_items(windows); i++) {
        g_autoptr(GtkWindow) window = g_list_model_get_item(windows, i);
        if (ADW_IS_MESSAGE_DIALOG(window) && g_strcmp0(adw_message_dialog_get_heading(ADW_MESSAGE_DIALOG(window)), "Choose a connection and setting") == 0) {
            refused = TRUE;
            gtk_window_destroy(window);
            break;
        }
    }
    g_assert_true(refused);
    g_object_unref(save);
    /* A disappearing selection must not silently become another single LAN
     * on either the first inspection or a later refresh. */
    json_array_remove_element(connections, 0);
    for (guint i = 0; i < 2; i++) {
        g_assert_true(show_connections(&test_app, json_node_get_object(json_parser_get_root(parser))));
        g_assert_cmpuint(test_app.lan_options->len, ==, 1);
        g_assert_cmpuint(gtk_drop_down_get_selected(test_app.access_network), ==, 1);
        g_auto(GStrv) disappeared = access_arguments(&test_app, &error);
        g_assert_null(disappeared); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
    }
}

static void test_access_rows_and_edit(void)
{
    select_access_profile("home");
    g_autoptr(JsonParser) parser = json_parser_new();
    const char *data = "{\"kind\":\"access\",\"profile\":\"home\",\"managed\":true,\"summary\":\"Verified host firewall permissions.\",\"rules\":[{\"id\":\"g123-456-789\",\"label\":\"Web server\",\"ports\":\"80,443\",\"protocol\":\"tcp\",\"source\":\"192.168.20.0/24\",\"interface\":\"wlp2s0\",\"expires_at\":0,\"state\":\"active\"}]}";
    g_assert_true(json_parser_load_from_data(parser, data, -1, NULL));
    access_fixture_recovery(json_node_get_object(json_parser_get_root(parser)), "ready", TRUE);
    g_assert_true(show_access(&test_app, json_node_get_object(json_parser_get_root(parser))));
    GtkWidget *row = gtk_widget_get_first_child(GTK_WIDGET(test_app.access_rules));
    g_assert_true(ADW_IS_ACTION_ROW(row));
    g_assert_cmpstr(adw_preferences_row_get_title(ADW_PREFERENCES_ROW(row)), ==, "Web server");
    g_assert_nonnull(strstr(adw_action_row_get_subtitle(ADW_ACTION_ROW(row)), "Active · 80,443/tcp"));
    g_assert_true(widget_has_label_text(row, "Edit")); g_assert_true(widget_has_label_text(row, "Revoke"));
    AccessRule *binding = g_object_get_data(G_OBJECT(row), "access-rule");
    access_edit_clicked(NULL, binding);
    g_assert_cmpstr(test_app.access_edit_id, ==, "g123-456-789");
    g_assert_true(gtk_widget_get_visible(test_app.access_custom));
    g_assert_true(gtk_widget_get_visible(test_app.access_address));
    g_autoptr(GError) error = NULL;
    g_auto(GStrv) args = access_arguments(&test_app, &error);
    g_assert_no_error(error); g_assert_cmpstr(args[1], ==, "update");
    g_assert_cmpstr(args[3], ==, "g123-456-789"); g_assert_cmpstr(args[4], ==, "80,443");
    access_cancel_edit(NULL, &test_app);
    g_assert_null(test_app.access_edit_id);
    g_assert_true(gtk_widget_get_first_child(GTK_WIDGET(test_app.access_rules)) == row);
    JsonObject *root = json_node_get_object(json_parser_get_root(parser));
    json_object_set_string_member(root, "profile", "missing-custom-profile");
    access_fixture_recovery(root, "ready", TRUE);
    g_assert_false(show_access(&test_app, root));
    g_assert_false(test_app.access_loaded);
    g_assert_null(gtk_widget_get_first_child(GTK_WIDGET(test_app.access_rules)));
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.access_summary), "missing from the current profile list"));
    g_auto(GStrv) unknown = access_arguments(&test_app, &error);
    g_assert_null(unknown); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
    json_object_set_string_member(root, "profile", "home");
    access_fixture_recovery(root, "ready", TRUE);
    g_assert_true(show_access(&test_app, root));
    g_auto(GStrv) refreshed = access_arguments(&test_app, &error);
    g_assert_no_error(error); g_assert_nonnull(refreshed);
    g_assert_cmpstr(refreshed[1], ==, "allow");
    g_assert_cmpstr(refreshed[2], ==, "home");
}

static void test_independent_encryption_and_details(void)
{
    g_autoptr(JsonParser) parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, "{\"profiles\":{\"available\":false},\"exposures\":{\"disk_encryption\":{\"state\":\"active\",\"summary\":\"Encryption backs the root filesystem.\"}}}", -1, NULL));
    JsonObject *root = json_node_get_object(json_parser_get_root(parser));
    StatusRow *disk = NULL;
    for (guint i = 0; i < test_app.status_rows->len; i++) {
        StatusRow *row = g_ptr_array_index(test_app.status_rows, i);
        if (g_str_equal(row->key, "disk_encryption")) disk = row;
    }
    g_assert_nonnull(disk); update_status_row(disk, root);
    g_assert_cmpstr(gtk_label_get_text(disk->badge), ==, "Encryption detected");
    g_assert_true(widget_has_label_text(GTK_WIDGET(disk->row), "Review"));
    const char *details = "{\"kind\":\"diagnostics\",\"topic\":\"disk_encryption\",\"title\":\"Storage encryption\",\"summary\":\"Root encryption verified; separate volumes listed below.\",\"findings\":[{\"title\":\"System filesystem\",\"state\":\"active\",\"detail\":\"Encrypted mapper backs this mount.\",\"source\":\"/dev/mapper/system-root\",\"action\":\"No change is required for this filesystem.\"}]}";
    g_assert_true(json_parser_load_from_data(parser, details, -1, NULL));
    show_diagnostics(&test_app, json_node_get_object(json_parser_get_root(parser)));
    g_assert_cmpstr(gtk_label_get_text(test_app.diagnostics_title), ==, "Storage encryption");
    g_assert_true(widget_has_label_text(GTK_WIDGET(test_app.diagnostics_findings), "/dev/mapper/system-root"));
    g_assert_true(widget_has_label_text(GTK_WIDGET(test_app.diagnostics_findings), "No change is required for this filesystem."));
    update_actions(&test_app);
    select_page(&test_app, "diagnostics");
    save_widget_png(GTK_WIDGET(test_app.window), "build/ui-storage-details.png");
}

static void test_access_recovery_readiness_and_draft(void)
{
    select_access_profile("office");
    access_cancel_edit(NULL, &test_app);
    g_autoptr(JsonObject) root = access_fixture("office", "incomplete", FALSE);
    JsonObject *rule = json_object_new();
    json_object_set_string_member(rule, "id", "g123-456-789");
    json_object_set_string_member(rule, "label", "Fixture web server");
    json_object_set_string_member(rule, "ports", "80,443");
    json_object_set_string_member(rule, "protocol", "tcp");
    json_object_set_string_member(rule, "source", "192.168.20.0/24");
    json_object_set_string_member(rule, "interface", "wlp2s0");
    json_object_set_string_member(rule, "state", "failed");
    json_object_set_int_member(rule, "expires_at", 0);
    json_array_add_object_element(array_member(root, "rules"), rule);
    g_assert_true(show_access(&test_app, root));
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.access_recovery_detail), "nftables reload was refused"));
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.access_recovery_detail), "Recorded assignment: office"));
    g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)));
    g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_apply)));
    g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_restore)));
    g_assert_true(gtk_widget_get_visible(GTK_WIDGET(test_app.access_last_change)));
    GtkWidget *row = gtk_widget_get_first_child(GTK_WIDGET(test_app.access_rules));
    AccessRule *binding = g_object_get_data(G_OBJECT(row), "access-rule");
    g_assert_nonnull(binding);
    g_assert_false(gtk_widget_get_sensitive(binding->revoke));
    access_revoke_clicked(NULL, binding);
    g_assert_null(test_app.operation);
    access_edit_clicked(NULL, binding);
    g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_ports)));
    gtk_editable_set_text(test_app.access_ports, "8080,8443");
    gtk_editable_set_text(test_app.access_source, "192.168.20.42");
    gtk_drop_down_set_selected(test_app.access_duration, 2);
    g_autoptr(GError) error = NULL;
    g_auto(GStrv) blocked = access_arguments(&test_app, &error);
    g_assert_null(blocked); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
    select_page(&test_app, "office");
    save_widget_png(GTK_WIDGET(test_app.window), "build/ui-firewall-recovery.png");

    access_fixture_recovery(root, "ready", TRUE);
    g_assert_true(show_access(&test_app, root));
    g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)));
    g_assert_cmpstr(test_app.access_edit_id, ==, "g123-456-789");
    g_assert_cmpstr(gtk_editable_get_text(test_app.access_ports), ==, "8080,8443");
    g_assert_cmpstr(gtk_editable_get_text(test_app.access_source), ==, "192.168.20.42");
    g_assert_cmpuint(gtk_drop_down_get_selected(test_app.access_duration), ==, 2);
    g_auto(GStrv) resumed = access_arguments(&test_app, &error);
    g_assert_no_error(error); g_assert_nonnull(resumed);
    g_assert_cmpstr(resumed[1], ==, "update");
    g_assert_cmpstr(resumed[2], ==, "office");
    g_assert_cmpstr(resumed[4], ==, "8080,8443");
    g_assert_null(test_app.operation);

    access_fixture_recovery(root, "drift", FALSE);
    g_assert_true(show_access(&test_app, root));
    g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)));
    g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_apply)));
    g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_restore)));
    g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_reconcile)));
    json_object_set_boolean_member(root, "ready", TRUE);
    g_assert_false(show_access(&test_app, root));
    for (guint i = 0; i < 7; i++) {
        access_fixture_recovery(root, "ready", TRUE);
        JsonObject *recovery = object_member(root, "recovery");
        if (i == 0) json_object_set_string_member(root, "ready", "true");
        if (i == 1) json_object_set_string_member(recovery, "can_apply", "true");
        if (i == 2) json_object_set_string_member(recovery, "transaction", "../../etc/shadow");
        if (i == 3) json_object_set_string_member(object_member(recovery, "observed"), "state", "complete");
        if (i == 4) json_object_remove_member(root, "recovery");
        if (i == 5) json_object_set_string_member(object_member(recovery, "observed"), "state", "unknown");
        if (i == 6) json_object_set_string_member(rule, "expires_at", "unexpected text");
        g_assert_false(show_access(&test_app, root));
        g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)));
        g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_apply)));
        g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_restore)));
        g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_reconcile)));
        g_assert_cmpstr(gtk_editable_get_text(test_app.access_ports), ==, "8080,8443");
        g_assert_cmpstr(test_app.access_edit_id, ==, "g123-456-789");
    }
    json_object_set_int_member(rule, "expires_at", 0);
    access_fixture_recovery(root, "unmanaged", TRUE);
    g_assert_true(show_access(&test_app, root));
    g_assert_true(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)));
    access_cancel_edit(NULL, &test_app);
}

static void test_access_profile_freshness(void)
{
    test_app.access_profile_initialized = FALSE;
    g_clear_pointer(&test_app.firewall_profile, g_free);
    g_autoptr(JsonParser) parser = json_parser_new();
    g_autofree gchar *snapshot = g_strdup_printf("{\"checked_at\":%" G_GINT64_FORMAT ",\"profiles\":{\"active\":\"home\",\"assignments\":{\"firewall\":\"office\"}},\"controls\":{},\"exposures\":{}}", g_get_real_time() / G_USEC_PER_SEC);
    g_assert_true(json_parser_load_from_data(parser, snapshot, -1, NULL));
    render_status(&test_app, json_node_get_object(json_parser_get_root(parser)));
    g_assert_cmpstr(selected_profile(&test_app, test_app.access_profile), ==, "office");
    render_status(&test_app, NULL);
    g_assert_cmpstr(selected_profile(&test_app, test_app.access_profile), ==, "office");
    g_assert_cmpstr(test_app.firewall_profile, ==, "office");
    access_cancel_edit(NULL, &test_app);
    test_app.access_edit_id = g_strdup("g123-456-789");
    test_app.access_edit_profile = g_strdup("office");
    for (guint i = 0; i < test_app.profile_ids->len; i++)
        if (g_str_equal(g_ptr_array_index(test_app.profile_ids, i), "home")) gtk_drop_down_set_selected(test_app.access_profile, i);
    g_assert_null(test_app.access_edit_id); g_assert_null(test_app.access_edit_profile);
    g_assert_null(gtk_widget_get_first_child(GTK_WIDGET(test_app.access_rules)));
    gtk_editable_set_text(test_app.access_ports, "8080,8443");
    test_app.access_edit_id = g_strdup("g123-456-789");
    test_app.access_edit_profile = g_strdup("home");
    JsonObject *assignments = object_member(object_member(json_node_get_object(json_parser_get_root(parser)), "profiles"), "assignments");
    json_object_set_string_member(assignments, "firewall", "unmanaged");
    render_status(&test_app, json_node_get_object(json_parser_get_root(parser)));
    g_assert_cmpstr(selected_profile(&test_app, test_app.access_profile), ==, "home");
    g_assert_cmpstr(test_app.access_edit_id, ==, "g123-456-789");
    g_assert_cmpstr(gtk_editable_get_text(test_app.access_ports), ==, "8080,8443");
    g_assert_false(gtk_widget_get_sensitive(GTK_WIDGET(test_app.access_submit)));
    access_cancel_edit(NULL, &test_app);
}

static void test_private_data_rejection_and_queue(void)
{
    Operation operation = {.app = &test_app, .title = "Refresh access permissions"};
    test_app.operation = &operation;
    handle_data_log(&test_app, "{\"kind\":\"access\"}");
    g_assert_false(operation.data_seen);
    operation.title = "Refresh connections";
    handle_data_log(&test_app, "{\"kind\":\"connections\",\"connections\":\"not-an-array\"}");
    g_assert_false(operation.data_seen);
    operation.title = "Review container local access";
    handle_data_log(&test_app, "{\"kind\":\"container-plan\",\"id\":\"invalid\",\"token\":\"invalid\"}");
    g_assert_false(operation.data_seen);
    test_app.operation = NULL;
    GtkWidget *dialog = adw_message_dialog_new(test_app.window, "Pending review", "Fixture only");
    test_app.preview = ADW_MESSAGE_DIALOG(dialog);
    test_app.private_refresh = 2U;
    update_actions(&test_app);
    g_assert_cmpuint(test_app.private_refresh_idle, ==, 0);
    test_app.preview = NULL;
    update_actions(&test_app);
    g_assert_cmpuint(test_app.private_refresh_idle, !=, 0);
    g_source_remove(test_app.private_refresh_idle); test_app.private_refresh_idle = 0; test_app.private_refresh = 0;
    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void refresh_test_drain(void)
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

int main(int argc, char **argv)
{
    if (argc == 3 && g_str_equal(argv[1], "--fixture"))
        return fixture(argv[2]);
    test_executable = g_canonicalize_filename(argv[0], NULL);
    g_test_init(&argc, &argv, NULL);
    adw_init();
    test_app.application = adw_application_new(OCTOSHIELD_APPLICATION_ID ".Test", G_APPLICATION_NON_UNIQUE);
    g_autoptr(GError) error = NULL;
    g_assert_true(g_application_register(G_APPLICATION(test_app.application), NULL, &error));
    activate(G_APPLICATION(test_app.application), &test_app);
    /* Tests explicitly supply each observed state. The real host cache must
     * not replace those fixtures while screenshots or async operations pump
     * the main context: a timer tick would correctly dismiss the fixture's
     * USB dialog because the runner has no corresponding connected device. */
    g_assert_cmpuint(test_app.refresh_timer, !=, 0);
    g_source_remove(test_app.refresh_timer);
    test_app.refresh_timer = 0;
    test_app.usb_automatic = TRUE;
    g_test_add_func("/ui/window/all-pages", test_window);
    g_test_add_func("/ui/window/group-text-escaping", test_group_text_escaping);
    g_test_add_func("/ui/window/accounts-panel-entry", test_accounts_entry);
    g_test_add_func("/ui/window/icons-decode-with-installed-loaders", test_icon_decoding);
    g_test_add_func("/ui/window/unchanged-brand-assets-follow-theme", test_brand_resources_and_theme);
    g_test_add_func("/ui/window/about-identity", test_about_identity);
    g_test_add_func("/ui/window/screenshots-real-pages-light-and-dark", test_page_screenshots);
    g_test_add_func("/ui/status/observed-partial-and-overrides", test_observed_status_and_overrides);
    g_test_add_func("/ui/status/repair-and-retired-control", test_repair_status_and_removed_control);
    g_test_add_func("/ui/status/catalog-preserves-selection", test_profile_catalog_selection);
    g_test_add_func("/ui/status/device-and-update-models", test_data_models);
    g_test_add_func("/ui/status/profile-choice-freshness", test_profile_choice_freshness);
    g_test_add_func("/ui/status/large-profile-and-device-records", test_large_data_records);
    g_test_add_func("/ui/access/guided-web-and-physical-networks", test_guided_access_and_connections);
    g_test_add_func("/ui/access/ambiguous-networks-and-unknown-privacy", test_ambiguous_network_and_privacy);
    g_test_add_func("/ui/access/inline-rules-and-atomic-edit", test_access_rows_and_edit);
    g_test_add_func("/ui/access/stale-status-retains-effective-profile", test_access_profile_freshness);
    g_test_add_func("/ui/access/recovery-readiness-and-preserved-draft", test_access_recovery_readiness_and_draft);
    g_test_add_func("/ui/diagnostics/private-data-rejection-and-queue", test_private_data_rejection_and_queue);
    g_test_add_func("/ui/diagnostics/encryption-independent-of-profile", test_independent_encryption_and_details);
    g_test_add_func("/ui/usb/prompt-deduplication-and-cancel", test_usb_prompt_deduplication_and_cancel);
    g_test_add_func("/ui/usb/approval-bound-before-authentication", test_usb_approval_is_bound_before_authentication);
    g_test_add_func("/ui/usb/profile-and-remembered-decisions", test_usb_profile_and_remembered_decisions);
    g_test_add_func("/ui/session/local-unlocked-graphical-owner", test_login_requires_local_unlocked_graphical_owner);
    g_test_add_func("/ui/session/reuses-authenticated-transport", test_session_reuses_authenticated_transport);
    g_test_add_func("/ui/session/firewall-recovery-reuses-session-and-retains-failure", test_access_recovery_uses_session_and_retains_failure);
    g_test_add_func("/ui/process/success-drains-both-streams", test_success);
    g_test_add_func("/ui/process/exit-without-done-fails", test_missing_done);
    g_test_add_func("/ui/process/done-with-bad-exit-fails", test_exit_mismatch);
    g_test_add_func("/ui/process/failure-change-state", test_failure_change_state);
    g_test_add_func("/ui/process/bounded-oversized-event", test_oversize);
    g_test_add_func("/ui/process/correlated-prompts-and-visible-review", test_confirmations);
    g_test_add_func("/ui/refresh/navigation-inflight-manual-failure-and-session", test_refresh_navigation_and_failures);
    g_test_add_func("/ui/refresh/resource-invalidation-metadata", test_refresh_resource_metadata);
    g_test_add_func("/ui/refresh/verified-access-without-original-restore", test_verified_access_without_original_restore);
    int result = g_test_run();
    branding_clear(&test_app);
    gtk_window_destroy(test_app.window);
    g_ptr_array_unref(test_app.operation_widgets);
    g_object_unref(test_app.application);
    g_free(test_executable);
    return result;
}
