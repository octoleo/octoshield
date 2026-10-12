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

static int fixture(const char *name)
{
    if (g_str_equal(name, "oversize")) {
        for (guint i = 0; i < MAX_PROTOCOL_LINE + 10; i++)
            fputc('x', stdout);
        fputc('\n', stdout);
        fputs("{\"type\":\"done\",\"success\":true}\n", stdout);
        return 0;
    }
    fputs("{\"type\":\"log\",\"text\":\"fixture inspection output\"}\n", stdout);
    fputs("fixture stderr diagnostic\n", stderr);
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
    g_assert_cmpuint(g_list_model_get_n_items(G_LIST_MODEL(pages)), ==, 6);
    g_object_unref(pages);
    g_assert_cmpuint(test_app.operation_widgets->len, >, 25);
    save_widget_png(GTK_WIDGET(test_app.window), "build/ui-overview.png");
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
        "\"usb\":{\"pending\":2,\"devices\":[{\"id\":17,\"state\":\"blocked\",\"label\":\"USB device\"}]}}",
        g_get_real_time() / G_USEC_PER_SEC);
    g_assert_true(json_parser_load_from_data(parser, snapshot, -1, NULL));
    render_status(&test_app, json_node_get_object(json_parser_get_root(parser)));
    g_assert_true(test_app.cache_valid);
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.overview_title), "individual overrides"));
    g_assert_nonnull(strstr(gtk_label_get_text(test_app.overview_title), "changes incomplete"));
    StatusRow *firewall = g_ptr_array_index(test_app.status_rows, 0);
    StatusRow *usb = g_ptr_array_index(test_app.status_rows, 1);
    g_assert_cmpstr(gtk_label_get_text(firewall->badge), ==, "Needs attention");
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

static void test_data_models(void)
{
    Operation operation = {.app = &test_app, .title = "Refresh device list"};
    test_app.operation = &operation;
    handle_data_log(&test_app, "[{\"id\":22,\"state\":\"blocked\",\"name\":\"<b>untrusted keyboard</b>\"},{\"id\":0,\"name\":\"invalid\"}]");
    g_assert_cmpuint(test_app.usb_ids->len, ==, 1);
    gtk_drop_down_set_selected(test_app.usb_devices, 0);
    g_assert_cmpstr(gtk_editable_get_text(test_app.usb_device_id), ==, "22");
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
    g_assert_cmpuint(test_app.usb_ids->len, ==, 100);
    g_string_free(devices, TRUE);
    g_string_free(operation.review, TRUE);
    g_string_free(operation.data_output, TRUE);
    test_app.operation = NULL;
    test_app.usb_inventory = FALSE;
    render_status(&test_app, NULL);
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
    static const char *const pages[] = {"overview", "protections", "usb", "office", "monitoring", "recovery"};
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

static void test_confirmations(void)
{
    launch_fixture("prompts");
    drain_operation(TRUE);
    g_autofree gchar *text = log_text();
    g_assert_nonnull(strstr(text, "Operation completed successfully."));
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
    g_test_add_func("/ui/window/all-pages", test_window);
    g_test_add_func("/ui/window/accounts-panel-entry", test_accounts_entry);
    g_test_add_func("/ui/window/icons-decode-with-installed-loaders", test_icon_decoding);
    g_test_add_func("/ui/window/unchanged-brand-assets-follow-theme", test_brand_resources_and_theme);
    g_test_add_func("/ui/window/about-identity", test_about_identity);
    g_test_add_func("/ui/window/screenshots-real-pages-light-and-dark", test_page_screenshots);
    g_test_add_func("/ui/status/observed-partial-and-overrides", test_observed_status_and_overrides);
    g_test_add_func("/ui/status/catalog-preserves-selection", test_profile_catalog_selection);
    g_test_add_func("/ui/status/device-and-update-models", test_data_models);
    g_test_add_func("/ui/status/large-profile-and-device-records", test_large_data_records);
    g_test_add_func("/ui/process/success-drains-both-streams", test_success);
    g_test_add_func("/ui/process/exit-without-done-fails", test_missing_done);
    g_test_add_func("/ui/process/done-with-bad-exit-fails", test_exit_mismatch);
    g_test_add_func("/ui/process/bounded-oversized-event", test_oversize);
    g_test_add_func("/ui/process/correlated-prompts-and-visible-review", test_confirmations);
    int result = g_test_run();
    branding_clear(&test_app);
    gtk_window_destroy(test_app.window);
    g_ptr_array_unref(test_app.operation_widgets);
    g_object_unref(test_app.application);
    g_free(test_executable);
    return result;
}
