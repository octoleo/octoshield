/* SPDX-License-Identifier: Apache-2.0 */
/* A separate test executable exercises the real frontend with a harmless
 * fixture child. Production cannot override the helper or bypass its root
 * guard. No system policy, password dialog, or privileged helper is invoked. */
#define main octoshield_application_entry
#include "../src/ui/octoshield-gtk.c"
#undef main

#include <stdio.h>
#include <stdlib.h>

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

static void test_accounts_entry(void)
{
    /* Match the upstream GNOME 46/50 Users desktop entry without launching a
     * password UI or forwarding user-supplied arguments. */
    g_assert_cmpstr(accounts_argv[0], ==, "/usr/bin/gnome-control-center");
    g_assert_cmpstr(accounts_argv[1], ==, "system");
    g_assert_cmpstr(accounts_argv[2], ==, "users");
    g_assert_null(accounts_argv[3]);
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
    test_app.application = adw_application_new("org.octoleo.OctoShield.Test", G_APPLICATION_NON_UNIQUE);
    g_autoptr(GError) error = NULL;
    g_assert_true(g_application_register(G_APPLICATION(test_app.application), NULL, &error));
    activate(G_APPLICATION(test_app.application), &test_app);
    g_test_add_func("/ui/window/all-pages", test_window);
    g_test_add_func("/ui/window/accounts-panel-entry", test_accounts_entry);
    g_test_add_func("/ui/process/success-drains-both-streams", test_success);
    g_test_add_func("/ui/process/exit-without-done-fails", test_missing_done);
    g_test_add_func("/ui/process/done-with-bad-exit-fails", test_exit_mismatch);
    g_test_add_func("/ui/process/bounded-oversized-event", test_oversize);
    g_test_add_func("/ui/process/correlated-prompts-and-visible-review", test_confirmations);
    int result = g_test_run();
    gtk_window_destroy(test_app.window);
    g_ptr_array_unref(test_app.operation_widgets);
    g_object_unref(test_app.application);
    g_free(test_executable);
    return result;
}
