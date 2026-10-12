/* SPDX-License-Identifier: Apache-2.0 */
/* OctoShield's unprivileged GNOME frontend. Privilege and policy stay in the
 * allowlisted helper; this process renders plain text and exchanges decisions. */
#include "protocol.h"

/* GTK's installed cleanup macros include an extra file-scope semicolon on
 * some distro releases. Keep project code pedantic without diagnosing that
 * external-header implementation detail. */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <adwaita.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include <gio/gio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define MAX_PROTOCOL_LINE (64U * 1024U)
#define MAX_LOG_CHARACTERS 180000
#define MAX_REVIEW_BYTES (256U * 1024U)

#ifndef OCTOSHIELD_VERSION
#define OCTOSHIELD_VERSION "0.2.0"
#endif

typedef struct App App;
typedef struct Operation Operation;

typedef struct {
    const char *id;
    const char *title;
    const char *description;
    const char *impact;
    gboolean privileged;
    gboolean changes;
    const char *args[5];
} Action;

/* This registry is also the parity map for the terminal interface. */
static const Action actions[] = {
    {"status", "Inspect system", "Firewall, listening ports, services and encryption information.", NULL, TRUE, FALSE, {"status", NULL}},
    {"firewall", "Network firewall", "Block unsolicited incoming traffic on Wi-Fi and Ethernet.", "Review and enable the UFW firewall policy. Existing inbound access may stop working. Docker and other container-published ports need separate review.", TRUE, TRUE, {"apply", "firewall", NULL}},
    {"usb-policy", "USB authorization", "Enroll trusted devices and block unfamiliar USB hardware.", "Disconnect untrusted devices now. Keep your required keyboard, mouse and trusted adapters connected. You will review the actual USB policy before enrollment; an incorrectly enrolled input device could lock you out.", TRUE, TRUE, {"apply", "usb", NULL}},
    {"network", "Connection privacy", "Review automatic connections and local network discovery.", "Restrict automatic connections and network discovery. Saved connections and local name resolution may change; use Office access to restore an individual trusted connection later.", TRUE, TRUE, {"apply", "network", NULL}},
    {"services", "Listening services", "Review SSH, discovery, printing and Bluetooth exposure.", "The helper will show the installed services affected and ask to disable that set. Remote sessions, Bluetooth input devices and printing may disconnect when their services are stopped.", TRUE, TRUE, {"apply", "services", NULL}},
    {"sudo", "Fresh administrator authentication", "Reduce reuse of cached sudo credentials.", "Require fresh authentication for sudo operations. You may be asked for your password more often. The helper checks its configuration before installing it.", TRUE, TRUE, {"apply", "sudo", NULL}},
    {"updates", "Security updates", "Enable Ubuntu's unattended security update mechanism.", "Install or configure unattended security updates. Package changes can take several minutes. Keep this window open while the package manager finishes.", TRUE, TRUE, {"apply", "updates", NULL}},
    {"apparmor", "Application confinement", "Enable the available AppArmor security service.", "Enable the installed AppArmor confinement mechanism. This does not create profiles for unconfined applications or guarantee that every application is confined.", TRUE, TRUE, {"apply", "apparmor", NULL}},
    {"monitor", "Security event monitoring", "Watch firewall, authentication and blocked USB events.", "Enable the system event collector. It reports meaningful thresholds and does not claim to detect passive sniffing or every attack. Desktop notifications are enabled separately for your user.", TRUE, TRUE, {"apply", "monitor", NULL}},
    {"desktop-apply", "Protect GNOME session", "Five-minute idle lock; removable-media and sharing controls.", "Set a five-minute idle timeout and immediate locking, disable media automount and autorun, and disable available per-user GNOME RDP/VNC controls. Your original settings are backed up privately.", FALSE, TRUE, {"desktop", "apply", NULL}},
    {"desktop-restore", "Restore GNOME settings", "Restore your recorded original desktop preferences.", "Restore the desktop settings recorded before OctoShield first changed them. Screen locking or desktop sharing may become less restrictive. System firewall and USB policy remain separate.", FALSE, TRUE, {"desktop", "restore", NULL}},
    {"desktop-status", "Inspect GNOME settings", "Read the current controls in your own desktop session.", NULL, FALSE, FALSE, {"desktop", "status", NULL}},
    {"usb-list", "Refresh device list", "Show USBGuard device IDs, rules and authorization state.", NULL, TRUE, FALSE, {"usb", "list", NULL}},
    {"monitor-status", "System monitor status", "Inspect the privileged collector's service state.", NULL, TRUE, FALSE, {"monitor", "status", NULL}},
    {"monitor-logs", "Recent monitor events", "Read recent collector service output.", NULL, TRUE, FALSE, {"monitor", "logs", NULL}},
    {"monitor-disable", "Disable system monitoring", "Stop collecting new security-event notifications.", "Stop the OctoShield system monitor. Existing firewall, USB and other preventive controls remain configured, but monitoring will stop reporting new events.", TRUE, TRUE, {"monitor", "disable", NULL}},
    {"notify-enable", "Enable desktop notifications", "Receive security alerts in this user's GNOME session.", "Enable this user's notification service. The system collector must already be installed and running. GNOME notification preferences and Do Not Disturb can affect visibility.", FALSE, TRUE, {"monitor", "enable-desktop", NULL}},
    {"notify-disable", "Disable desktop notifications", "Stop notifications for this user without changing policy.", "Disable the notification service for this user. The system collector and preventive controls continue independently.", FALSE, TRUE, {"monitor", "disable-desktop", NULL}},
    {"notify-status", "Desktop notification status", "Inspect this user's notification service.", NULL, FALSE, FALSE, {"monitor", "status", NULL}},
    {"backups", "List configuration backups", "Show recorded system changes and recovery transactions.", NULL, TRUE, FALSE, {"backups", NULL}},
    {"recovery", "Read recovery guide", "Inspect the installed recovery and backup instructions.", NULL, FALSE, FALSE, {"recovery", NULL}}
};

typedef enum {
    INPUT_USB_ALLOW,
    INPUT_USB_BLOCK,
    INPUT_OFFICE_FIREWALL,
    INPUT_OFFICE_NETWORK,
    INPUT_OFFICE_SERVICE,
    INPUT_BACKUP_SHOW
} InputAction;

typedef struct {
    App *app;
    const Action *action;
    InputAction input_action;
    GtkEditable *first;
    GtkEditable *second;
    GtkSwitch *permanent;
    GtkDropDown *service;
} Binding;

typedef struct {
    App *app;
    gchar *title;
    gchar *impact;
    GStrv argv;
    gboolean changes;
} Request;

typedef struct {
    Operation *operation;
    GInputStream *input;
    GByteArray *line;
    gboolean protocol;
    gboolean eof;
    gboolean discarding;
} Reader;

struct Operation {
    App *app;
    GSubprocess *process;
    GOutputStream *answers;
    Reader out;
    Reader err;
    gchar *title;
    GString *review;
    gchar *deferred_confirmation;
    guint64 last_prompt_id;
    guint64 current_prompt_id;
    guint64 deferred_prompt_id;
    gchar *answer;
    gboolean exited;
    gboolean exit_success;
    gboolean done_seen;
    gboolean reported_success;
    gboolean protocol_failed;
    gboolean waiting_confirmation;
    gboolean answer_pending;
    gboolean input_closed;
    gboolean review_truncated;
};

struct App {
    AdwApplication *application;
    GtkWindow *window;
    AdwToastOverlay *toasts;
    GtkStack *pages;
    GtkTextBuffer *log;
    GtkTextView *log_view;
    GtkExpander *details;
    GtkLabel *activity;
    GtkSpinner *spinner;
    GPtrArray *operation_widgets;
    GtkWidget *decline;
    AdwMessageDialog *confirmation;
    AdwMessageDialog *preview;
    Operation *operation;
    gboolean smoke_test;
};

static void operation_maybe_finish(Operation *operation);
static void update_actions(App *app);
static void read_next(Reader *reader);
static void show_confirmation(Operation *operation, guint64 id, const char *text);

static const Action *find_action(const char *id)
{
    for (gsize i = 0; i < G_N_ELEMENTS(actions); i++) {
        if (g_str_equal(actions[i].id, id))
            return &actions[i];
    }
    g_assert_not_reached();
}

static void toast(App *app, const char *message)
{
    adw_toast_overlay_add_toast(app->toasts, adw_toast_new(message));
}

static void append_log(App *app, const char *text)
{
    if (app->operation != NULL && app->operation->review != NULL) {
        Operation *operation = app->operation;
        gsize size = strlen(text);
        if (!operation->review_truncated && size + operation->review->len + 1 <= MAX_REVIEW_BYTES) {
            g_string_append(operation->review, text);
            g_string_append_c(operation->review, '\n');
        } else if (!operation->review_truncated) {
            operation->review_truncated = TRUE;
            g_string_append(operation->review, "\n[Review output exceeded the display limit. Further approval is disabled; inspect the policy through the terminal interface.]\n");
        }
    }
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->log, &end);
    gtk_text_buffer_insert(app->log, &end, text, -1);
    gtk_text_buffer_insert(app->log, &end, "\n", 1);
    gint count = gtk_text_buffer_get_char_count(app->log);
    if (count > MAX_LOG_CHARACTERS) {
        GtkTextIter start;
        GtkTextIter cutoff;
        gtk_text_buffer_get_start_iter(app->log, &start);
        gtk_text_buffer_get_iter_at_offset(app->log, &cutoff, count - MAX_LOG_CHARACTERS / 2);
        gtk_text_iter_forward_line(&cutoff);
        gtk_text_buffer_delete(app->log, &start, &cutoff);
        gtk_text_buffer_get_start_iter(app->log, &start);
        gtk_text_buffer_insert(app->log, &start, "[Older output removed to keep this view responsive.]\n", -1);
    }
    gtk_text_buffer_get_end_iter(app->log, &end);
    gtk_text_view_scroll_to_iter(app->log_view, &end, 0.0, FALSE, 0.0, 1.0);
}

static void show_error(App *app, const char *title, const char *message)
{
    GtkWidget *dialog = adw_message_dialog_new(app->window, title, message);
    adw_message_dialog_add_response(ADW_MESSAGE_DIALOG(dialog), "close", "Close");
    adw_message_dialog_set_close_response(ADW_MESSAGE_DIALOG(dialog), "close");
    gtk_window_present(GTK_WINDOW(dialog));
}

static GtkWidget *plain_text_scroller(const char *text)
{
    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 12);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 12);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(view), 12);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(view), 12);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), text, -1);
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scroll), 130);
    gtk_scrolled_window_set_max_content_height(GTK_SCROLLED_WINDOW(scroll), 360);
    gtk_scrolled_window_set_propagate_natural_height(GTK_SCROLLED_WINDOW(scroll), TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_add_css_class(scroll, "card");
    return scroll;
}

static void close_answers(Operation *operation)
{
    if (!operation->input_closed) {
        operation->input_closed = TRUE;
        /* Closing the decision channel denies a future prompt. Never signal a
         * privileged process in the middle of a configuration mutation. */
        if (!operation->answer_pending)
            g_output_stream_close(operation->answers, NULL, NULL);
    }
}

static void protocol_error(Operation *operation, const char *message)
{
    if (!operation->protocol_failed) {
        operation->protocol_failed = TRUE;
        append_log(operation->app, message);
        append_log(operation->app, "The decision channel was closed. Waiting for the helper to finish; changes already made are not automatically undone.");
    }
    close_answers(operation);
    g_clear_pointer(&operation->deferred_confirmation, g_free);
    operation->waiting_confirmation = FALSE;
    if (operation->app->confirmation != NULL) {
        AdwMessageDialog *dialog = operation->app->confirmation;
        operation->app->confirmation = NULL;
        adw_message_dialog_response(dialog, "decline");
    }
    update_actions(operation->app);
}

static void answer_written(GObject *source, GAsyncResult *result, gpointer data)
{
    Operation *operation = data;
    g_autoptr(GError) error = NULL;
    gsize written = 0;
    if (!g_output_stream_write_all_finish(G_OUTPUT_STREAM(source), result, &written, &error)) {
        g_autofree gchar *message = g_strdup_printf("Unable to send the decision: %s", error->message);
        protocol_error(operation, message);
    }
    operation->answer_pending = FALSE;
    g_clear_pointer(&operation->answer, g_free);
    if (operation->input_closed)
        g_output_stream_close(operation->answers, NULL, NULL);
    if (operation->deferred_confirmation != NULL && !operation->protocol_failed &&
        !operation->exited && !operation->done_seen) {
        g_autofree gchar *prompt = g_steal_pointer(&operation->deferred_confirmation);
        show_confirmation(operation, operation->deferred_prompt_id, prompt);
    }
    update_actions(operation->app);
    operation_maybe_finish(operation);
}

static void confirmation_response(AdwMessageDialog *dialog, const char *response, gpointer data)
{
    App *app = data;
    if (app->confirmation == dialog)
        app->confirmation = NULL;
    Operation *operation = app->operation;
    if (operation == NULL || !operation->waiting_confirmation)
        return;
    operation->waiting_confirmation = FALSE;
    if (operation->input_closed || operation->exited)
        return;
    gboolean accepted = g_str_equal(response, "accept");
    if (operation->review_truncated)
        accepted = FALSE;
    append_log(app, accepted ? "Decision: continue with the reviewed change." : "Decision: decline this change.");
    g_string_truncate(operation->review, 0);
    operation->review_truncated = FALSE;
    operation->answer_pending = TRUE;
    operation->answer = g_strdup_printf("%" G_GUINT64_FORMAT " %s\n", operation->current_prompt_id, accepted ? "yes" : "no");
    g_output_stream_write_all_async(operation->answers, operation->answer, strlen(operation->answer), G_PRIORITY_DEFAULT,
                                   NULL, answer_written, operation);
    gtk_label_set_text(app->activity, accepted ? "Applying the reviewed change…" : "Waiting for the helper after your decision…");
    update_actions(app);
}

static void show_confirmation(Operation *operation, guint64 id, const char *text)
{
    App *app = operation->app;
    operation->waiting_confirmation = TRUE;
    operation->current_prompt_id = id;
    gtk_label_set_text(app->activity, "Review required — the helper is waiting for your decision");
    GtkWidget *dialog = adw_message_dialog_new(app->window, "Review this change", "The helper has paused. Review the captured policy and the request below before continuing.");
    g_autofree gchar *review = g_strconcat(operation->review->str, "\nREQUEST\n", text, NULL);
    adw_message_dialog_set_extra_child(ADW_MESSAGE_DIALOG(dialog), plain_text_scroller(review));
    adw_message_dialog_add_responses(ADW_MESSAGE_DIALOG(dialog), "decline", "Decline", "accept", "Continue", NULL);
    adw_message_dialog_set_response_appearance(ADW_MESSAGE_DIALOG(dialog), "accept", ADW_RESPONSE_SUGGESTED);
    adw_message_dialog_set_default_response(ADW_MESSAGE_DIALOG(dialog), "decline");
    adw_message_dialog_set_close_response(ADW_MESSAGE_DIALOG(dialog), "decline");
    adw_message_dialog_set_response_enabled(ADW_MESSAGE_DIALOG(dialog), "accept", !operation->review_truncated);
    app->confirmation = ADW_MESSAGE_DIALOG(dialog);
    g_signal_connect(dialog, "response", G_CALLBACK(confirmation_response), app);
    update_actions(app);
    gtk_window_present(GTK_WINDOW(dialog));
}

static void handle_line(Reader *reader)
{
    Operation *operation = reader->operation;
    if (reader->line->len == 0)
        return;
    if (!reader->protocol) {
        g_autofree gchar *safe = octoshield_text_sanitize((const gchar *)reader->line->data, reader->line->len);
        append_log(operation->app, safe);
        return;
    }
    OctoshieldEvent event = {0};
    g_autoptr(GError) error = NULL;
    if (!octoshield_event_parse((const gchar *)reader->line->data, reader->line->len, &event, &error)) {
        g_autofree gchar *message = g_strdup_printf("Invalid helper response: %s", error->message);
        protocol_error(operation, message);
        return;
    }
    if (operation->done_seen) {
        protocol_error(operation, "The helper sent data after its completion result.");
        octoshield_event_clear(&event);
        return;
    }
    switch (event.type) {
    case OCTOSHIELD_EVENT_LOG:
        append_log(operation->app, event.text);
        break;
    case OCTOSHIELD_EVENT_CONFIRM:
        if (event.id <= operation->last_prompt_id || operation->waiting_confirmation ||
            operation->deferred_confirmation != NULL || operation->input_closed) {
            protocol_error(operation, "The helper sent an unexpected or overlapping confirmation request.");
        } else {
            operation->last_prompt_id = event.id;
            if (operation->answer_pending) {
                operation->deferred_confirmation = g_strdup(event.text);
                operation->deferred_prompt_id = event.id;
            } else {
                show_confirmation(operation, event.id, event.text);
            }
        }
        break;
    case OCTOSHIELD_EVENT_DONE:
        if (operation->waiting_confirmation || operation->deferred_confirmation != NULL) {
            protocol_error(operation, "The helper finished while a decision was still pending.");
        }
        operation->done_seen = TRUE;
        operation->reported_success = event.success;
        break;
    default:
        protocol_error(operation, "The helper sent an unsupported event.");
        break;
    }
    octoshield_event_clear(&event);
}

static void bytes_read(GObject *source, GAsyncResult *result, gpointer data)
{
    Reader *reader = data;
    Operation *operation = reader->operation;
    g_autoptr(GError) error = NULL;
    g_autoptr(GBytes) bytes = g_input_stream_read_bytes_finish(G_INPUT_STREAM(source), result, &error);
    if (bytes == NULL || g_bytes_get_size(bytes) == 0) {
        if (error != NULL) {
            g_autofree gchar *message = g_strdup_printf("Unable to read helper output: %s", error->message);
            protocol_error(operation, message);
        }
        if (reader->line->len != 0 && !reader->discarding) {
            if (reader->protocol)
                protocol_error(operation, "The helper closed its output in the middle of a JSON event.");
            else
                handle_line(reader);
        }
        reader->eof = TRUE;
        operation_maybe_finish(operation);
        return;
    }
    gsize size = 0;
    const guint8 *buffer = g_bytes_get_data(bytes, &size);
    for (gsize i = 0; i < size; i++) {
        if (buffer[i] == '\n') {
            if (!reader->discarding)
                handle_line(reader);
            g_byte_array_set_size(reader->line, 0);
            reader->discarding = FALSE;
        } else if (!reader->discarding) {
            if (reader->line->len >= MAX_PROTOCOL_LINE) {
                if (reader->protocol)
                    protocol_error(operation, "A helper response exceeded the allowed line length.");
                else
                    append_log(operation->app, "[An oversized diagnostic line was omitted.]");
                reader->discarding = TRUE;
                g_byte_array_set_size(reader->line, 0);
            } else {
                g_byte_array_append(reader->line, &buffer[i], 1);
            }
        }
    }
    read_next(reader);
}

static void read_next(Reader *reader)
{
    g_input_stream_read_bytes_async(reader->input, 4096, G_PRIORITY_DEFAULT, NULL, bytes_read, reader);
}

static void process_waited(GObject *source, GAsyncResult *result, gpointer data)
{
    Operation *operation = data;
    g_autoptr(GError) error = NULL;
    operation->exit_success = g_subprocess_wait_finish(G_SUBPROCESS(source), result, &error) &&
                              g_subprocess_get_successful(operation->process);
    operation->exited = TRUE;
    if (error != NULL) {
        g_autofree gchar *message = g_strdup_printf("Unable to collect the helper's exit result: %s", error->message);
        append_log(operation->app, message);
    }
    /* The pipe can contain the final event even after wait reports exit. */
    operation_maybe_finish(operation);
}

static void operation_maybe_finish(Operation *operation)
{
    if (!operation->exited || !operation->out.eof || !operation->err.eof || operation->answer_pending)
        return;
    App *app = operation->app;
    gboolean success = operation->exit_success && operation->done_seen &&
                       operation->reported_success && !operation->protocol_failed;
    operation->waiting_confirmation = FALSE;
    if (app->confirmation != NULL) {
        AdwMessageDialog *dialog = app->confirmation;
        app->confirmation = NULL;
        adw_message_dialog_response(dialog, "decline");
    }
    close_answers(operation);
    if (!operation->done_seen)
        append_log(app, "No valid completion result was received. Authentication may have been cancelled, or the helper may have failed. Review the details before retrying.");
    if (success) {
        gtk_label_set_text(app->activity, "Operation completed — review the details below");
        append_log(app, "Operation completed successfully.");
        toast(app, "Operation completed");
    } else {
        gtk_label_set_text(app->activity, "Operation declined or failed — review the details");
        append_log(app, "Operation declined or failed. Earlier confirmed changes may still be in effect; consult Recovery before retrying.");
        toast(app, "Review the operation details");
    }
    gtk_spinner_stop(app->spinner);
    gtk_widget_set_visible(GTK_WIDGET(app->spinner), FALSE);
    app->operation = NULL;
    g_byte_array_unref(operation->out.line);
    g_byte_array_unref(operation->err.line);
    g_object_unref(operation->process);
    g_string_free(operation->review, TRUE);
    g_free(operation->deferred_confirmation);
    g_free(operation->answer);
    g_free(operation->title);
    g_free(operation);
    update_actions(app);
}

static void request_free(Request *request)
{
    g_free(request->title);
    g_free(request->impact);
    g_strfreev(request->argv);
    g_free(request);
}

static void launch_request(Request *request)
{
    App *app = request->app;
    if (app->operation != NULL || app->smoke_test) {
        request_free(request);
        return;
    }
    g_autoptr(GError) error = NULL;
    GSubprocess *process = g_subprocess_newv((const gchar *const *)request->argv,
                                           G_SUBPROCESS_FLAGS_STDIN_PIPE |
                                           G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                                           G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
    if (process == NULL) {
        show_error(app, "Unable to start this operation", error->message);
        request_free(request);
        update_actions(app);
        return;
    }
    Operation *operation = g_new0(Operation, 1);
    operation->app = app;
    operation->process = process;
    operation->answers = g_subprocess_get_stdin_pipe(process);
    operation->title = g_strdup(request->title);
    operation->review = g_string_new(NULL);
    operation->out = (Reader){operation, g_subprocess_get_stdout_pipe(process), g_byte_array_new(), TRUE, FALSE, FALSE};
    operation->err = (Reader){operation, g_subprocess_get_stderr_pipe(process), g_byte_array_new(), FALSE, FALSE, FALSE};
    app->operation = operation;
    gtk_text_buffer_set_text(app->log, "", 0);
    append_log(app, request->title);
    append_log(app, "Review this output and every requested confirmation. Closing this window does not interrupt a running system change.");
    gtk_expander_set_expanded(app->details, TRUE);
    gtk_label_set_text(app->activity, "Working — administrator authentication may be requested…");
    gtk_widget_set_visible(GTK_WIDGET(app->spinner), TRUE);
    gtk_spinner_start(app->spinner);
    update_actions(app);
    read_next(&operation->out);
    read_next(&operation->err);
    g_subprocess_wait_async(process, NULL, process_waited, operation);
    request_free(request);
}

static void preview_response(AdwMessageDialog *dialog, const char *response, gpointer data)
{
    Request *request = data;
    App *app = request->app;
    if (app->preview == dialog)
        app->preview = NULL;
    if (g_str_equal(response, "continue"))
        launch_request(request);
    else
        request_free(request);
    update_actions(app);
}

static void start_action(App *app, const char *title, const char *impact, gboolean privileged,
                         gboolean changes, gsize argc, const char *const *args)
{
    if (app->operation != NULL || app->preview != NULL || app->smoke_test) {
        toast(app, "Finish the current operation before starting another");
        return;
    }
    g_autoptr(GError) error = NULL;
    GStrv argv = octoshield_action_argv(privileged, argc, args, &error);
    if (argv == NULL) {
        show_error(app, "Check the entered values", error->message);
        return;
    }
    Request *request = g_new0(Request, 1);
    request->app = app;
    request->title = g_strdup(title);
    request->impact = g_strdup(impact);
    request->argv = argv;
    request->changes = changes;
    if (!changes) {
        launch_request(request);
        return;
    }
    GtkWidget *dialog = adw_message_dialog_new(app->window, title, impact);
    adw_message_dialog_add_responses(ADW_MESSAGE_DIALOG(dialog), "cancel", "Cancel", "continue", "Review and continue", NULL);
    adw_message_dialog_set_response_appearance(ADW_MESSAGE_DIALOG(dialog), "continue", ADW_RESPONSE_SUGGESTED);
    adw_message_dialog_set_default_response(ADW_MESSAGE_DIALOG(dialog), "cancel");
    adw_message_dialog_set_close_response(ADW_MESSAGE_DIALOG(dialog), "cancel");
    app->preview = ADW_MESSAGE_DIALOG(dialog);
    g_signal_connect(dialog, "response", G_CALLBACK(preview_response), request);
    update_actions(app);
    gtk_window_present(GTK_WINDOW(dialog));
}

static void fixed_action_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    Binding *binding = data;
    const Action *action = binding->action;
    gsize count = 0;
    while (action->args[count] != NULL)
        count++;
    start_action(binding->app, action->title, action->impact, action->privileged,
                 action->changes, count, action->args);
}

static void input_action_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    Binding *binding = data;
    const char *first = binding->first != NULL ? gtk_editable_get_text(binding->first) : NULL;
    const char *second = binding->second != NULL ? gtk_editable_get_text(binding->second) : NULL;
    const char *args[5] = {NULL};
    const char *title = "Review change";
    gboolean changes = TRUE;
    gsize count = 0;
    g_autofree gchar *impact = NULL;
    switch (binding->input_action) {
    case INPUT_USB_ALLOW:
        args[0] = "usb"; args[1] = "allow"; args[2] = first; count = 3;
        if (gtk_switch_get_active(binding->permanent)) {
            args[3] = "--permanent"; count = 4;
            impact = g_strdup_printf("Review USB device %s and add a persistent authorization rule. Approve only hardware you trust; a device can expose keyboard or network interfaces as well as storage.", first);
        } else {
            impact = g_strdup_printf("Review USB device %s and authorize its current connection only. Reconnecting or restarting requires another authorization. This does not scan files or prove the device is safe.", first);
        }
        title = "Authorize USB device";
        break;
    case INPUT_USB_BLOCK:
        args[0] = "usb"; args[1] = "block"; args[2] = first; count = 3;
        title = "Block USB device";
        impact = g_strdup_printf("Block USB device %s. If it is a keyboard, mouse, network adapter or mounted storage, access can stop immediately. Safely unmount storage before blocking it.", first);
        break;
    case INPUT_OFFICE_FIREWALL:
        args[0] = "office"; args[1] = "firewall"; args[2] = first; args[3] = second; count = 4;
        title = "Allow a narrow office connection";
        impact = g_strdup_printf("Allow incoming TCP port %s only from IPv4 subnet %s. Use a subnet you control and expose only the service you need. The rest of the firewall policy stays configured.", first, second);
        break;
    case INPUT_OFFICE_NETWORK:
        args[0] = "office"; args[1] = "network"; args[2] = first; count = 3;
        title = "Trust a saved network";
        impact = g_strdup_printf("Enable automatic connection for saved profile UUID %s. Verify the profile and its security settings before trusting it.", first);
        break;
    case INPUT_OFFICE_SERVICE: {
        static const char *units[] = {"ssh.service", "avahi-daemon.service", "bluetooth.service", "cups.service"};
        guint index = gtk_drop_down_get_selected(binding->service);
        if (index >= G_N_ELEMENTS(units))
            return;
        args[0] = "office"; args[1] = "service"; args[2] = units[index]; count = 3;
        title = "Restore an office service";
        impact = g_strdup_printf("Unmask, enable and start %s and its related activation units. This restores service availability; any required firewall exception is a separate decision.", units[index]);
        break;
    }
    case INPUT_BACKUP_SHOW:
        args[0] = "backup-show"; args[1] = first; count = 2;
        title = "Inspect backup transaction";
        changes = FALSE;
        break;
    }
    start_action(binding->app, title, impact, TRUE, changes, count, args);
}

static void update_actions(App *app)
{
    gboolean enabled = app->operation == NULL && app->preview == NULL && !app->smoke_test;
    for (guint i = 0; i < app->operation_widgets->len; i++)
        gtk_widget_set_sensitive(g_ptr_array_index(app->operation_widgets, i), enabled);
    gtk_widget_set_visible(app->decline, app->operation != NULL && app->operation->waiting_confirmation);
}

static GtkWidget *action_button(App *app, const char *id, const char *label, gboolean suggested)
{
    GtkWidget *button = gtk_button_new_with_label(label);
    gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
    if (suggested)
        gtk_widget_add_css_class(button, "suggested-action");
    Binding *binding = g_new0(Binding, 1);
    binding->app = app;
    binding->action = find_action(id);
    g_object_set_data_full(G_OBJECT(button), "binding", binding, g_free);
    g_signal_connect(button, "clicked", G_CALLBACK(fixed_action_clicked), binding);
    g_ptr_array_add(app->operation_widgets, button);
    return button;
}

static GtkWidget *action_row(App *app, const char *id, const char *button_label, const char *icon)
{
    const Action *action = find_action(id);
    GtkWidget *row = adw_action_row_new();
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), action->title);
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    adw_action_row_set_subtitle(ADW_ACTION_ROW(row), action->description);
    adw_action_row_set_subtitle_lines(ADW_ACTION_ROW(row), 2);
    if (icon != NULL)
        adw_action_row_add_prefix(ADW_ACTION_ROW(row), gtk_image_new_from_icon_name(icon));
    GtkWidget *button = action_button(app, id, button_label, FALSE);
    adw_action_row_add_suffix(ADW_ACTION_ROW(row), button);
    adw_action_row_set_activatable_widget(ADW_ACTION_ROW(row), button);
    return row;
}

static GtkWidget *group_new(GtkWidget *page, const char *title, const char *description)
{
    GtkWidget *group = adw_preferences_group_new();
    adw_preferences_group_set_title(ADW_PREFERENCES_GROUP(group), title);
    if (description != NULL)
        adw_preferences_group_set_description(ADW_PREFERENCES_GROUP(group), description);
    gtk_box_append(GTK_BOX(page), group);
    return group;
}

static void group_add(GtkWidget *group, GtkWidget *row)
{
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), row);
}

static GtkWidget *text_label(const char *text, const char *css_class)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    if (css_class != NULL)
        gtk_widget_add_css_class(label, css_class);
    return label;
}

static GtkWidget *page_new(App *app, const char *name, const char *title, const char *subtitle)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
    gtk_widget_set_margin_top(box, 24);
    gtk_widget_set_margin_bottom(box, 28);
    gtk_widget_set_margin_start(box, 28);
    gtk_widget_set_margin_end(box, 28);
    GtkWidget *heading = gtk_box_new(GTK_ORIENTATION_VERTICAL, 7);
    gtk_box_append(GTK_BOX(heading), text_label(title, "title-1"));
    gtk_box_append(GTK_BOX(heading), text_label(subtitle, "dim-label"));
    gtk_box_append(GTK_BOX(box), heading);
    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_maximum_size(ADW_CLAMP(clamp), 960);
    adw_clamp_set_tightening_threshold(ADW_CLAMP(clamp), 700);
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), clamp);
    gtk_stack_add_named(app->pages, scroll, name);
    return box;
}

static GtkWidget *input_row(GtkWidget *group, const char *title)
{
    GtkWidget *row = adw_entry_row_new();
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), title);
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    adw_entry_row_set_input_purpose(ADW_ENTRY_ROW(row), GTK_INPUT_PURPOSE_FREE_FORM);
    group_add(group, row);
    return row;
}

static GtkWidget *input_button(App *app, const char *label, InputAction action,
                               GtkWidget *first, GtkWidget *second, GtkWidget *permanent, GtkWidget *service)
{
    GtkWidget *button = gtk_button_new_with_label(label);
    gtk_widget_set_halign(button, GTK_ALIGN_END);
    gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
    Binding *binding = g_new0(Binding, 1);
    binding->app = app;
    binding->input_action = action;
    binding->first = first != NULL ? GTK_EDITABLE(first) : NULL;
    binding->second = second != NULL ? GTK_EDITABLE(second) : NULL;
    binding->permanent = permanent != NULL ? GTK_SWITCH(permanent) : NULL;
    binding->service = service != NULL ? GTK_DROP_DOWN(service) : NULL;
    g_object_set_data_full(G_OBJECT(button), "binding", binding, g_free);
    g_signal_connect(button, "clicked", G_CALLBACK(input_action_clicked), binding);
    g_ptr_array_add(app->operation_widgets, button);
    return button;
}

static GtkWidget *control_row(const char *title, const char *subtitle, GtkWidget *control)
{
    GtkWidget *row = adw_action_row_new();
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), title);
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    if (subtitle != NULL)
        adw_action_row_set_subtitle(ADW_ACTION_ROW(row), subtitle);
    gtk_widget_set_valign(control, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix(ADW_ACTION_ROW(row), control);
    return row;
}

static void accounts_waited(GObject *source, GAsyncResult *result, gpointer data)
{
    (void)data;
    g_subprocess_wait_finish(G_SUBPROCESS(source), result, NULL);
    g_object_unref(source);
}

static void accounts_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    g_autoptr(GError) error = NULL;
    GSubprocess *process = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &error,
                                          "/usr/bin/gnome-control-center", "user-accounts", NULL);
    if (process == NULL)
        show_error(app, "Unable to open GNOME Accounts", error->message);
    else
        g_subprocess_wait_async(process, NULL, accounts_waited, NULL);
}

static void build_overview(App *app)
{
    GtkWidget *page = page_new(app, "overview", "A prepared laptop. A clearer picture.",
                               "Review your protections before the conference, then adjust individual controls when you return to the office.");
    GtkWidget *hero = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 18);
    gtk_widget_add_css_class(hero, "shield-hero");
    GtkWidget *icon = gtk_image_new_from_icon_name("security-high-symbolic");
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 52);
    gtk_box_append(GTK_BOX(hero), icon);
    GtkWidget *copy = gtk_box_new(GTK_ORIENTATION_VERTICAL, 7);
    gtk_widget_set_hexpand(copy, TRUE);
    gtk_box_append(GTK_BOX(copy), text_label("Start with an inspection", "title-2"));
    gtk_box_append(GTK_BOX(copy), text_label("Read your current firewall, services, network and storage information. Inspection is evidence to review, not a guarantee of protection.", NULL));
    gtk_box_append(GTK_BOX(hero), copy);
    gtk_box_append(GTK_BOX(hero), action_button(app, "status", "Inspect system", TRUE));
    gtk_box_append(GTK_BOX(page), hero);
    GtkWidget *group = group_new(page, "Prepare for an untrusted environment", "Every system change requests administrator authentication and its own review.");
    group_add(group, action_row(app, "firewall", "Review", "network-wireless-symbolic"));
    group_add(group, action_row(app, "usb-policy", "Review", "drive-removable-media-symbolic"));
    group_add(group, action_row(app, "desktop-apply", "Review", "system-lock-screen-symbolic"));
    GtkWidget *notice = text_label("Keep physical control of the laptop. Lock it when you step away, and shut it down before leaving it unattended. OctoShield strengthens existing Linux controls; it cannot eliminate every vulnerability.", "dim-label");
    gtk_box_append(GTK_BOX(page), notice);
}

static void build_protections(App *app)
{
    GtkWidget *page = page_new(app, "protections", "Protections", "Choose the controls that fit this laptop. Impact details are shown before each change.");
    GtkWidget *group = group_new(page, "System protection", "These operations use the system's administrator authentication dialog.");
    static const char *ids[] = {"firewall", "usb-policy", "network", "services", "sudo", "updates", "apparmor", "monitor"};
    static const char *icons[] = {"network-workgroup-symbolic", "drive-removable-media-symbolic", "network-wireless-symbolic", "preferences-system-symbolic", "dialog-password-symbolic", "software-update-available-symbolic", "security-high-symbolic", "utilities-system-monitor-symbolic"};
    for (gsize i = 0; i < G_N_ELEMENTS(ids); i++)
        group_add(group, action_row(app, ids[i], "Review", icons[i]));
    group = group_new(page, "Your GNOME session", "Desktop settings are changed as your normal user and have their own private baseline.");
    group_add(group, action_row(app, "desktop-apply", "Review", "system-lock-screen-symbolic"));
    group_add(group, action_row(app, "desktop-status", "Inspect", "dialog-information-symbolic"));
    group_add(group, action_row(app, "desktop-restore", "Restore…", "edit-undo-symbolic"));
    GtkWidget *accounts = gtk_button_new_with_label("Open Accounts");
    g_signal_connect(accounts, "clicked", G_CALLBACK(accounts_clicked), app);
    g_ptr_array_add(app->operation_widgets, accounts);
    group_add(group, control_row("Change your password", "Use GNOME Accounts. OctoShield never receives or stores your password.", accounts));
}

static void build_usb(App *app)
{
    GtkWidget *page = page_new(app, "usb", "USB devices", "Inspect a device's identity and interfaces before allowing it. Device names can be supplied by the device itself.");
    GtkWidget *group = group_new(page, "Inspect the connected hardware", "The device list appears in Operation details. Use the numeric ID from that current list.");
    group_add(group, action_row(app, "usb-list", "Refresh", "view-refresh-symbolic"));
    group_add(group, action_row(app, "usb-policy", "Review policy", "security-high-symbolic"));
    group = group_new(page, "Authorize or block one device", "An unknown device remains blocked until you explicitly approve it through administrator authentication.");
    GtkWidget *device = input_row(group, "Numeric device ID");
    adw_entry_row_set_input_purpose(ADW_ENTRY_ROW(device), GTK_INPUT_PURPOSE_DIGITS);
    GtkWidget *permanent = gtk_switch_new();
    group_add(group, control_row("Remember authorization", "Off: current connection only. On: persist a trusted-device rule.", permanent));
    GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_halign(buttons, GTK_ALIGN_END);
    GtkWidget *block = input_button(app, "Block device…", INPUT_USB_BLOCK, device, NULL, NULL, NULL);
    GtkWidget *allow = input_button(app, "Review authorization…", INPUT_USB_ALLOW, device, NULL, permanent, NULL);
    gtk_widget_add_css_class(allow, "suggested-action");
    gtk_box_append(GTK_BOX(buttons), block);
    gtk_box_append(GTK_BOX(buttons), allow);
    gtk_box_append(GTK_BOX(page), buttons);
    gtk_box_append(GTK_BOX(page), text_label("USB authorization is separate from file scanning and encryption. Blocking your active input or network device can disconnect it immediately; unmount storage before blocking it.", "dim-label"));
}

static void build_office(App *app)
{
    GtkWidget *page = page_new(app, "office", "Office access", "Restore only the access you need. Each exception is narrow and reviewed before it is applied.");
    GtkWidget *group = group_new(page, "Allow an incoming TCP service", "Choose one port and a trusted IPv4 subnet. A universal /0 source is intentionally refused.");
    GtkWidget *port = input_row(group, "TCP port · 1–65535");
    adw_entry_row_set_input_purpose(ADW_ENTRY_ROW(port), GTK_INPUT_PURPOSE_DIGITS);
    GtkWidget *subnet = input_row(group, "Trusted IPv4 subnet · for example 192.168.1.0/24");
    gtk_box_append(GTK_BOX(page), input_button(app, "Review firewall exception…", INPUT_OFFICE_FIREWALL, port, subnet, NULL, NULL));
    group = group_new(page, "Reconnect to a trusted saved network", "Inspect the system first to identify the exact saved connection UUID.");
    GtkWidget *uuid = input_row(group, "Saved connection UUID");
    gtk_box_append(GTK_BOX(page), input_button(app, "Review automatic connection…", INPUT_OFFICE_NETWORK, uuid, NULL, NULL, NULL));
    group = group_new(page, "Restore a service", "Starting a listening service and allowing its firewall traffic are separate decisions.");
    static const char *const services[] = {"SSH · ssh.service", "Local discovery · avahi-daemon.service", "Bluetooth · bluetooth.service", "Printing · cups.service", NULL};
    GtkWidget *service = gtk_drop_down_new_from_strings(services);
    group_add(group, control_row("Service", NULL, service));
    gtk_box_append(GTK_BOX(page), input_button(app, "Review service restoration…", INPUT_OFFICE_SERVICE, NULL, NULL, NULL, service));
    group = group_new(page, "Inspect before changing access", NULL);
    group_add(group, action_row(app, "status", "Inspect", "dialog-information-symbolic"));
}

static void build_monitoring(App *app)
{
    GtkWidget *page = page_new(app, "monitoring", "Security monitoring", "See meaningful activity from existing system security events, with restrained notifications in your GNOME session.");
    GtkWidget *group = group_new(page, "System event collector", "Collects repeated firewall blocks, trusted authentication failures and USBGuard denials. Passive network sniffing cannot reliably be detected from the laptop.");
    group_add(group, action_row(app, "monitor", "Enable…", "utilities-system-monitor-symbolic"));
    group_add(group, action_row(app, "monitor-status", "Inspect", "dialog-information-symbolic"));
    group_add(group, action_row(app, "monitor-logs", "View", "text-x-generic-symbolic"));
    group_add(group, action_row(app, "monitor-disable", "Disable…", "media-playback-stop-symbolic"));
    group = group_new(page, "Your desktop notifications", "Enable the system collector first, then enable notifications for this user. Check GNOME's notification settings if alerts are hidden.");
    group_add(group, action_row(app, "notify-enable", "Enable…", "preferences-system-notifications-symbolic"));
    group_add(group, action_row(app, "notify-status", "Inspect", "dialog-information-symbolic"));
    group_add(group, action_row(app, "notify-disable", "Disable…", "notifications-disabled-symbolic"));
    gtk_box_append(GTK_BOX(page), text_label("An alert describes observed events, not proof of compromise. If activity is unexpected, inspect it and consider disconnecting Wi-Fi or Ethernet while you investigate.", "dim-label"));
}

static void build_recovery(App *app)
{
    GtkWidget *page = page_new(app, "recovery", "Recovery & change records", "Review the recorded changes before restoring access. There is no one-click global security reset.");
    GtkWidget *group = group_new(page, "Recovery information", "System configuration backups remain administrator-only. The detail view shows a transaction's action record, not stored configuration secrets.");
    group_add(group, action_row(app, "recovery", "Read", "help-browser-symbolic"));
    group_add(group, action_row(app, "backups", "List", "document-open-recent-symbolic"));
    GtkWidget *transaction = input_row(group, "Backup transaction ID · copy from the backup list");
    gtk_box_append(GTK_BOX(page), input_button(app, "Inspect transaction", INPUT_BACKUP_SHOW, transaction, NULL, NULL, NULL));
    group = group_new(page, "Restore your desktop baseline", "This restores the original recorded GNOME preferences; use Office access for narrow system exceptions.");
    group_add(group, action_row(app, "desktop-restore", "Review restore…", "edit-undo-symbolic"));
    gtk_box_append(GTK_BOX(page), text_label("If a system operation fails after an earlier step completed, some changes may already be in effect. Keep the operation details and inspect the recorded transaction before retrying or recovering.", "dim-label"));
}

static void navigation_selected(GtkListBox *list, GtkListBoxRow *row, gpointer data)
{
    (void)list;
    App *app = data;
    if (row != NULL)
        gtk_stack_set_visible_child_name(app->pages, g_object_get_data(G_OBJECT(row), "page-name"));
}

static GtkWidget *build_sidebar(App *app)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_size_request(box, 190, -1);
    gtk_widget_add_css_class(box, "shield-sidebar");
    GtkWidget *brand = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_start(brand, 18);
    gtk_widget_set_margin_top(brand, 22);
    gtk_widget_set_margin_bottom(brand, 15);
    gtk_box_append(GTK_BOX(brand), gtk_image_new_from_icon_name("security-high-symbolic"));
    gtk_box_append(GTK_BOX(brand), text_label("OctoShield", "title-3"));
    gtk_box_append(GTK_BOX(box), brand);
    GtkWidget *list = gtk_list_box_new();
    gtk_widget_add_css_class(list, "navigation-sidebar");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    static const char *const navigation[][3] = {
        {"overview", "Overview", "view-grid-symbolic"},
        {"protections", "Protections", "security-high-symbolic"},
        {"usb", "USB devices", "drive-removable-media-symbolic"},
        {"office", "Office access", "network-workgroup-symbolic"},
        {"monitoring", "Monitoring", "utilities-system-monitor-symbolic"},
        {"recovery", "Recovery", "edit-undo-symbolic"}
    };
    for (gsize i = 0; i < G_N_ELEMENTS(navigation); i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *content = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_widget_set_margin_top(content, 10);
        gtk_widget_set_margin_bottom(content, 10);
        gtk_widget_set_margin_start(content, 10);
        gtk_widget_set_margin_end(content, 10);
        gtk_box_append(GTK_BOX(content), gtk_image_new_from_icon_name(navigation[i][2]));
        gtk_box_append(GTK_BOX(content), text_label(navigation[i][1], NULL));
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), content);
        g_object_set_data(G_OBJECT(row), "page-name", (gpointer)navigation[i][0]);
        gtk_list_box_append(GTK_LIST_BOX(list), row);
    }
    g_signal_connect(list, "row-selected", G_CALLBACK(navigation_selected), app);
    gtk_box_append(GTK_BOX(box), list);
    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_vexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(box), spacer);
    GtkWidget *footer = text_label("OCTOLEO SUITE\nRuns as your desktop user", "dim-label");
    gtk_widget_set_margin_start(footer, 18);
    gtk_widget_set_margin_end(footer, 14);
    gtk_widget_set_margin_bottom(footer, 22);
    gtk_box_append(GTK_BOX(box), footer);
    gtk_list_box_select_row(GTK_LIST_BOX(list), gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));
    return box;
}

static void decline_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    if (app->confirmation != NULL)
        adw_message_dialog_response(app->confirmation, "decline");
}

static void copy_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    GtkTextIter start;
    GtkTextIter end;
    gtk_text_buffer_get_bounds(app->log, &start, &end);
    g_autofree gchar *text = gtk_text_buffer_get_text(app->log, &start, &end, FALSE);
    gdk_clipboard_set_text(gtk_widget_get_clipboard(GTK_WIDGET(app->window)), text);
    toast(app, "Operation details copied");
}

static GtkWidget *build_activity(App *app)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(box, 24);
    gtk_widget_set_margin_end(box, 24);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 14);
    GtkWidget *status = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    app->spinner = GTK_SPINNER(gtk_spinner_new());
    gtk_widget_set_visible(GTK_WIDGET(app->spinner), FALSE);
    gtk_box_append(GTK_BOX(status), GTK_WIDGET(app->spinner));
    app->activity = GTK_LABEL(text_label("Ready — choose an inspection or protection to review", "dim-label"));
    gtk_widget_set_hexpand(GTK_WIDGET(app->activity), TRUE);
    gtk_box_append(GTK_BOX(status), GTK_WIDGET(app->activity));
    app->decline = gtk_button_new_with_label("Decline current change");
    gtk_widget_set_visible(app->decline, FALSE);
    g_signal_connect(app->decline, "clicked", G_CALLBACK(decline_clicked), app);
    gtk_box_append(GTK_BOX(status), app->decline);
    gtk_box_append(GTK_BOX(box), status);
    app->details = GTK_EXPANDER(gtk_expander_new("Operation details"));
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scroll), 150);
    gtk_scrolled_window_set_max_content_height(GTK_SCROLLED_WINDOW(scroll), 230);
    app->log_view = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_editable(app->log_view, FALSE);
    gtk_text_view_set_cursor_visible(app->log_view, TRUE);
    gtk_text_view_set_monospace(app->log_view, TRUE);
    gtk_text_view_set_wrap_mode(app->log_view, GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(app->log_view, 12);
    gtk_text_view_set_right_margin(app->log_view, 12);
    gtk_text_view_set_top_margin(app->log_view, 12);
    gtk_text_view_set_bottom_margin(app->log_view, 12);
    app->log = gtk_text_view_get_buffer(app->log_view);
    gtk_text_buffer_set_text(app->log, "Operation output will appear here. No protection has been applied by opening this app.", -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), GTK_WIDGET(app->log_view));
    gtk_widget_add_css_class(scroll, "card");
    gtk_box_append(GTK_BOX(content), scroll);
    GtkWidget *copy = gtk_button_new_with_label("Copy details");
    gtk_widget_set_halign(copy, GTK_ALIGN_END);
    gtk_widget_add_css_class(copy, "flat");
    g_signal_connect(copy, "clicked", G_CALLBACK(copy_clicked), app);
    gtk_box_append(GTK_BOX(content), copy);
    gtk_expander_set_child(app->details, content);
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(app->details));
    return box;
}

static gboolean window_close_requested(GtkWindow *window, gpointer data)
{
    (void)window;
    App *app = data;
    if (app->operation != NULL) {
        if (app->confirmation != NULL)
            adw_message_dialog_response(app->confirmation, "decline");
        toast(app, "Wait for the running operation to finish. A pending confirmation has been declined.");
        return TRUE;
    }
    if (app->preview != NULL)
        adw_message_dialog_response(app->preview, "cancel");
    return FALSE;
}

static gboolean smoke_finished(gpointer data)
{
    App *app = data;
    gtk_window_close(app->window);
    return G_SOURCE_REMOVE;
}

static void activate(GApplication *application, gpointer data)
{
    App *app = data;
    if (app->window != NULL) {
        gtk_window_present(app->window);
        return;
    }
    app->window = GTK_WINDOW(adw_application_window_new(GTK_APPLICATION(application)));
    gtk_window_set_title(app->window, "OctoShield");
    gtk_window_set_default_size(app->window, 1100, 820);
    gtk_widget_set_size_request(GTK_WIDGET(app->window), 820, 600);
    g_signal_connect(app->window, "close-request", G_CALLBACK(window_close_requested), app);
    app->operation_widgets = g_ptr_array_new();
    app->pages = GTK_STACK(gtk_stack_new());
    gtk_stack_set_transition_type(app->pages, GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_set_transition_duration(app->pages, 130);
    gtk_widget_set_vexpand(GTK_WIDGET(app->pages), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(app->pages), TRUE);
    app->toasts = ADW_TOAST_OVERLAY(adw_toast_overlay_new());
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *header = adw_header_bar_new();
    adw_header_bar_set_title_widget(ADW_HEADER_BAR(header), adw_window_title_new("OctoShield", "Laptop protection · OctoLeo"));
    adw_header_bar_pack_end(ADW_HEADER_BAR(header), action_button(app, "status", "Inspect system", FALSE));
    gtk_box_append(GTK_BOX(outer), header);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    build_overview(app);
    build_protections(app);
    build_usb(app);
    build_office(app);
    build_monitoring(app);
    build_recovery(app);
    gtk_box_append(GTK_BOX(body), build_sidebar(app));
    gtk_box_append(GTK_BOX(body), gtk_separator_new(GTK_ORIENTATION_VERTICAL));
    GtkWidget *main = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_hexpand(main, TRUE);
    gtk_box_append(GTK_BOX(main), GTK_WIDGET(app->pages));
    gtk_box_append(GTK_BOX(main), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
    gtk_box_append(GTK_BOX(main), build_activity(app));
    gtk_box_append(GTK_BOX(body), main);
    gtk_widget_set_vexpand(body, TRUE);
    gtk_box_append(GTK_BOX(outer), body);
    adw_toast_overlay_set_child(app->toasts, outer);
    adw_application_window_set_content(ADW_APPLICATION_WINDOW(app->window), GTK_WIDGET(app->toasts));
    GtkCssProvider *css = gtk_css_provider_new();
    const char *style = ".shield-sidebar { background: alpha(@window_fg_color,0.035); }"
                        ".shield-hero { border-radius: 16px; padding: 22px; background: alpha(@accent_bg_color,0.12); }"
                        ".shield-hero image { color: @accent_color; }";
    gtk_css_provider_load_from_string(css, style);
    gtk_style_context_add_provider_for_display(gtk_widget_get_display(GTK_WIDGET(app->window)), GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
    update_actions(app);
    gtk_window_present(app->window);
    if (app->smoke_test)
        g_timeout_add(700, smoke_finished, app);
}

int main(int argc, char **argv)
{
    gboolean smoke_test = FALSE;
    if (argc == 2 && g_str_equal(argv[1], "--version")) {
        g_print("OctoShield %s\n", OCTOSHIELD_VERSION);
        return 0;
    }
    if (argc == 2 && g_str_equal(argv[1], "--help")) {
        g_print("Usage: octoshield-gtk [--version | --smoke-test]\n\nOpen OctoShield in your normal GNOME user session.\n--smoke-test opens a read-only window briefly for display tests.\n");
        return 0;
    }
    if (argc == 2 && g_str_equal(argv[1], "--smoke-test")) {
        smoke_test = TRUE;
        argc = 1;
    } else if (argc != 1) {
        g_printerr("Unknown argument. Run octoshield-gtk --help.\n");
        return 2;
    }
    if (geteuid() == 0) {
        g_printerr("Run OctoShield as your normal GNOME user, without sudo. Administrator authentication is requested only for system operations.\n");
        return 1;
    }
    if (g_getenv("SSH_CONNECTION") != NULL || g_getenv("SSH_TTY") != NULL) {
        g_printerr("Run OctoShield from your local GNOME session, not through SSH.\n");
        return 1;
    }
    /* A helper may exit between a prompt and the asynchronous response write.
     * Let GIO report EPIPE instead of terminating the desktop application. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        g_printerr("Unable to initialize safe helper communication.\n");
        return 1;
    }
    App app = {0};
    app.smoke_test = smoke_test;
    app.application = adw_application_new("org.octoleo.OctoShield", smoke_test ? G_APPLICATION_NON_UNIQUE : G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app.application, "activate", G_CALLBACK(activate), &app);
    int result = g_application_run(G_APPLICATION(app.application), argc, argv);
    if (app.operation_widgets != NULL)
        g_ptr_array_unref(app.operation_widgets);
    g_object_unref(app.application);
    return result;
}
