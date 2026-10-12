/* SPDX-License-Identifier: Apache-2.0 */
/* Deterministic tests for the actual GTK controller's asynchronous boundaries.
 * No backend, polkit helper, native security command, or child process is run. */
#define main octoshield_application_entry_for_test
#include "../../src/ui/octoshield-gtk.c"
#undef main

typedef struct {
    App app;
    Operation operation;
} Fixture;

static void fixture_setup(Fixture *fixture, gconstpointer data)
{
    (void)data;
    App *app = &fixture->app;
    Operation *operation = &fixture->operation;
    app->window = GTK_WINDOW(gtk_window_new());
    app->operation_widgets = g_ptr_array_new();
    app->toasts = ADW_TOAST_OVERLAY(adw_toast_overlay_new());
    adw_toast_overlay_set_child(app->toasts, build_activity(app));
    gtk_window_set_child(app->window, GTK_WIDGET(app->toasts));
    operation->app = app;
    operation->title = g_strdup("Synthetic operation");
    operation->review = g_string_new(NULL);
    operation->answers = g_memory_output_stream_new_resizable();
    operation->out = (Reader){operation, NULL, g_byte_array_new(), TRUE, FALSE, FALSE};
    operation->err = (Reader){operation, NULL, g_byte_array_new(), FALSE, FALSE, FALSE};
    app->operation = operation;
}

static void wait_for_answer(Fixture *fixture)
{
    gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (fixture->operation.answer_pending && g_get_monotonic_time() < deadline) {
        g_main_context_iteration(NULL, FALSE);
        g_usleep(1000);
    }
    g_assert_false(fixture->operation.answer_pending);
}

static void fixture_teardown(Fixture *fixture, gconstpointer data)
{
    (void)data;
    App *app = &fixture->app;
    Operation *operation = &fixture->operation;
    wait_for_answer(fixture);
    operation->waiting_confirmation = FALSE;
    if (app->confirmation != NULL) {
        GtkWindow *dialog = GTK_WINDOW(app->confirmation);
        app->confirmation = NULL;
        gtk_window_destroy(dialog);
    }
    close_answers(operation);
    app->operation = NULL;
    g_object_unref(operation->answers);
    g_byte_array_unref(operation->out.line);
    g_byte_array_unref(operation->err.line);
    g_string_free(operation->review, TRUE);
    g_free(operation->title);
    g_free(operation->deferred_confirmation);
    g_free(operation->answer);
    gtk_window_destroy(app->window);
    g_ptr_array_unref(app->operation_widgets);
}

static void receive(Fixture *fixture, const char *line)
{
    Reader *reader = &fixture->operation.out;
    g_byte_array_set_size(reader->line, 0);
    g_byte_array_append(reader->line, (const guint8 *)line, strlen(line));
    handle_line(reader);
    g_byte_array_set_size(reader->line, 0);
}

static void queue_answer_without_dispatching_callback(Fixture *fixture)
{
    Operation *operation = &fixture->operation;
    operation->last_prompt_id = 1;
    operation->current_prompt_id = 1;
    operation->answer = g_strdup("1 yes\n");
    operation->answer_pending = TRUE;
    g_output_stream_write_all_async(operation->answers, operation->answer,
                                   strlen(operation->answer), G_PRIORITY_DEFAULT,
                                   NULL, answer_written, operation);
    g_assert_true(operation->answer_pending);
}

static void test_next_confirmation_before_write_callback(Fixture *fixture,
                                                         gconstpointer data)
{
    (void)data;
    queue_answer_without_dispatching_callback(fixture);
    receive(fixture, "{\"type\":\"log\",\"text\":\"Exact second review\"}");
    receive(fixture, "{\"type\":\"confirm\",\"id\":2,\"text\":\"Second decision?\"}");
    g_assert_false(fixture->operation.protocol_failed);
    g_assert_cmpstr(fixture->operation.deferred_confirmation, ==, "Second decision?");
    g_assert_null(fixture->app.confirmation);
    wait_for_answer(fixture);
    g_assert_null(fixture->operation.deferred_confirmation);
    g_assert_nonnull(fixture->app.confirmation);
    g_assert_cmpuint(fixture->operation.current_prompt_id, ==, 2);
    g_assert_false(fixture->operation.protocol_failed);
}

static void test_done_before_write_callback(Fixture *fixture, gconstpointer data)
{
    (void)data;
    queue_answer_without_dispatching_callback(fixture);
    receive(fixture, "{\"type\":\"done\",\"success\":true}");
    g_assert_true(fixture->operation.done_seen);
    g_assert_true(fixture->operation.reported_success);
    g_assert_false(fixture->operation.protocol_failed);
    wait_for_answer(fixture);
    g_assert_false(fixture->operation.protocol_failed);
}

static void test_confirmation_contains_exact_review(Fixture *fixture,
                                                   gconstpointer data)
{
    (void)data;
    receive(fixture, "{\"type\":\"log\",\"text\":\"7: Keyboard hash abc123 via-port 1-1 <b>literal</b>\"}");
    receive(fixture, "{\"type\":\"confirm\",\"id\":1,\"text\":\"Authorize the reviewed device?\"}");
    AdwMessageDialog *dialog = fixture->app.confirmation;
    g_assert_nonnull(dialog);
    g_assert_cmpstr(adw_message_dialog_get_default_response(dialog), ==, "decline");
    g_assert_cmpstr(adw_message_dialog_get_close_response(dialog), ==, "decline");
    GtkWidget *scroll = adw_message_dialog_get_extra_child(dialog);
    g_assert_true(GTK_IS_SCROLLED_WINDOW(scroll));
    GtkWidget *view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));
    g_assert_true(GTK_IS_TEXT_VIEW(view));
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    GtkTextIter start;
    GtkTextIter end;
    gtk_text_buffer_get_bounds(buffer, &start, &end);
    g_autofree gchar *text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
    g_assert_nonnull(strstr(text, "7: Keyboard hash abc123 via-port 1-1 <b>literal</b>"));
    g_assert_nonnull(strstr(text, "Authorize the reviewed device?"));
    g_assert_false(gtk_text_view_get_editable(GTK_TEXT_VIEW(view)));
}

static void test_stale_confirmation_denied(Fixture *fixture, gconstpointer data)
{
    (void)data;
    fixture->operation.last_prompt_id = 2;
    receive(fixture, "{\"type\":\"confirm\",\"id\":2,\"text\":\"Stale decision\"}");
    g_assert_true(fixture->operation.protocol_failed);
    g_assert_true(fixture->operation.input_closed);
    g_assert_false(fixture->operation.waiting_confirmation);
    g_assert_null(fixture->app.confirmation);
    g_assert_true(g_output_stream_is_closed(fixture->operation.answers));
}

static void test_oversized_review_cannot_be_approved(Fixture *fixture,
                                                   gconstpointer data)
{
    (void)data;
    g_autofree gchar *text = g_strnfill(MAX_REVIEW_BYTES + 1, 'x');
    append_log(&fixture->app, text);
    receive(fixture, "{\"type\":\"confirm\",\"id\":1,\"text\":\"Approve truncated review?\"}");
    g_assert_true(fixture->operation.review_truncated);
    g_assert_nonnull(fixture->app.confirmation);
    g_assert_false(adw_message_dialog_get_response_enabled(fixture->app.confirmation, "accept"));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    adw_init();
    g_test_add("/ui-lifecycle/next-confirm-before-write-callback", Fixture, NULL,
               fixture_setup, test_next_confirmation_before_write_callback, fixture_teardown);
    g_test_add("/ui-lifecycle/done-before-write-callback", Fixture, NULL,
               fixture_setup, test_done_before_write_callback, fixture_teardown);
    g_test_add("/ui-lifecycle/exact-review-visible", Fixture, NULL,
               fixture_setup, test_confirmation_contains_exact_review, fixture_teardown);
    g_test_add("/ui-lifecycle/stale-confirmation-denied", Fixture, NULL,
               fixture_setup, test_stale_confirmation_denied, fixture_teardown);
    g_test_add("/ui-lifecycle/truncated-review-denied", Fixture, NULL,
               fixture_setup, test_oversized_review_cannot_be_approved, fixture_teardown);
    return g_test_run();
}
