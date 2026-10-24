/* SPDX-License-Identifier: Apache-2.0 */
/* OctoShield's unprivileged GNOME frontend. Privilege and policy stay in the
 * allowlisted helper; this process renders plain text and exchanges decisions. */
/* Keep API/deprecation checks anchored to the supported Ubuntu 24.04 baseline
 * when compiling the same source with newer Ubuntu desktop libraries. */
#define _GNU_SOURCE
#define ADW_VERSION_MIN_REQUIRED ADW_VERSION_1_4
#define ADW_VERSION_MAX_ALLOWED ADW_VERSION_1_5
#define GDK_VERSION_MIN_REQUIRED GDK_VERSION_4_12
#define GDK_VERSION_MAX_ALLOWED GDK_VERSION_4_14
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
#include <json-glib/json-glib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PROTOCOL_LINE (64U * 1024U)
#define MAX_LOG_CHARACTERS 180000
#define MAX_REVIEW_BYTES (256U * 1024U)
#define OCTOSHIELD_APPLICATION_ID "io.vdm.OctoShield"
#define BRAND_RESOURCE_DARK "/io/vdm/OctoShield/branding/OctoShield-dark.png"
#define BRAND_RESOURCE_LIGHT "/io/vdm/OctoShield/branding/OctoShield-light.png"

#ifndef OCTOSHIELD_VERSION
#define OCTOSHIELD_VERSION "1.3.1"
#endif

typedef struct App App;
typedef struct Operation Operation;
typedef struct UsbDevice UsbDevice;
typedef struct Session Session;

/* A fixed-size native image container controls layout without creating resized
 * bitmap assets. GtkPicture scales the original embedded PNG for the display. */
typedef struct {
    GtkWidget parent_instance;
    GtkWidget *picture;
    int width;
    int height;
} OctoshieldBrand;

typedef GtkWidgetClass OctoshieldBrandClass;
G_DEFINE_TYPE(OctoshieldBrand, octoshield_brand, GTK_TYPE_WIDGET)

static void octoshield_brand_measure(GtkWidget *widget, GtkOrientation orientation,
                                     int for_size, int *minimum, int *natural,
                                     int *minimum_baseline, int *natural_baseline)
{
    (void)for_size;
    OctoshieldBrand *brand = (OctoshieldBrand *)widget;
    *minimum = *natural = orientation == GTK_ORIENTATION_HORIZONTAL ? brand->width : brand->height;
    *minimum_baseline = *natural_baseline = -1;
}

static void octoshield_brand_size_allocate(GtkWidget *widget, int width, int height, int baseline)
{
    OctoshieldBrand *brand = (OctoshieldBrand *)widget;
    gtk_widget_allocate(brand->picture, width, height, baseline, NULL);
}

static void octoshield_brand_snapshot(GtkWidget *widget, GtkSnapshot *snapshot)
{
    OctoshieldBrand *brand = (OctoshieldBrand *)widget;
    gtk_widget_snapshot_child(widget, brand->picture, snapshot);
}

static void octoshield_brand_dispose(GObject *object)
{
    OctoshieldBrand *brand = (OctoshieldBrand *)object;
    g_clear_pointer(&brand->picture, gtk_widget_unparent);
    G_OBJECT_CLASS(octoshield_brand_parent_class)->dispose(object);
}

static void octoshield_brand_class_init(OctoshieldBrandClass *class)
{
    GtkWidgetClass *widget_class = GTK_WIDGET_CLASS(class);
    widget_class->measure = octoshield_brand_measure;
    widget_class->size_allocate = octoshield_brand_size_allocate;
    widget_class->snapshot = octoshield_brand_snapshot;
    gtk_widget_class_set_accessible_role(widget_class, GTK_ACCESSIBLE_ROLE_PRESENTATION);
    G_OBJECT_CLASS(class)->dispose = octoshield_brand_dispose;
}

static void octoshield_brand_init(OctoshieldBrand *brand)
{
    brand->picture = gtk_picture_new();
    gtk_picture_set_content_fit(GTK_PICTURE(brand->picture), GTK_CONTENT_FIT_CONTAIN);
    gtk_picture_set_can_shrink(GTK_PICTURE(brand->picture), TRUE);
    gtk_picture_set_alternative_text(GTK_PICTURE(brand->picture), "OctoShield lion and shield");
    gtk_widget_set_parent(brand->picture, GTK_WIDGET(brand));
}

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
    {"firewall", "Network firewall", "Apply the Conference firewall profile on Wi-Fi and Ethernet.", "Apply the Conference profile's incoming policy while allowing outgoing connections. The helper previews the policy and existing inbound rules before changing them. Container-published ports need separate review.", TRUE, TRUE, {"apply", "firewall", NULL}},
    {"usb-policy", "USB authorization", "Enroll trusted devices and block unfamiliar USB hardware.", "Disconnect untrusted devices now. Keep your required keyboard, mouse and trusted adapters connected. You will review the actual USB policy before enrollment; an incorrectly enrolled input device could lock you out.", TRUE, TRUE, {"apply", "usb", NULL}},
    {"network", "Connection privacy", "Apply the Conference profile's connection and discovery settings.", "Apply the Conference profile's automatic connection and discovery choices. Saved connections and local name resolution may change; Access & exceptions can restore an individual trusted connection.", TRUE, TRUE, {"apply", "network", NULL}},
    {"services", "Listening services", "Apply the Conference profile's service settings.", "The helper previews how the Conference profile changes installed services. Remote sessions, Bluetooth input devices and printing may disconnect when their services are stopped.", TRUE, TRUE, {"apply", "services", NULL}},
    {"sudo", "Fresh administrator authentication", "Reduce reuse of cached sudo credentials.", "Require fresh authentication for sudo operations. You may be asked for your password more often. The helper checks its configuration before installing it.", TRUE, TRUE, {"apply", "sudo", NULL}},
    {"updates", "Security updates", "Enable Ubuntu's unattended security update mechanism.", "Install or configure unattended security updates. Package changes can take several minutes. Keep this window open while the package manager finishes.", TRUE, TRUE, {"apply", "updates", NULL}},
    {"apparmor", "Application confinement", "Enable the available AppArmor security service.", "Enable the installed AppArmor confinement mechanism. This does not create profiles for unconfined applications or guarantee that every application is confined.", TRUE, TRUE, {"apply", "apparmor", NULL}},
    {"monitor", "Security event monitoring", "Watch firewall, authentication and blocked USB events.", "Enable the system event collector. It reports meaningful thresholds and does not claim to detect passive sniffing or every attack. Desktop notifications are enabled separately for your user.", TRUE, TRUE, {"apply", "monitor", NULL}},
    {"desktop-apply", "Protect GNOME session", "Five-minute idle lock; removable-media and sharing controls.", "Set a five-minute idle timeout and immediate locking, disable media automount and autorun, and disable available per-user GNOME RDP/VNC controls. Your original settings are backed up privately.", FALSE, TRUE, {"desktop", "apply", NULL}},
    {"desktop-restore", "Restore GNOME settings", "Restore your recorded original desktop preferences.", "Restore the desktop settings recorded before OctoShield first changed them. Screen locking or desktop sharing may become less restrictive. System firewall and USB policy remain separate.", FALSE, TRUE, {"desktop", "restore", NULL}},
    {"desktop-status", "Inspect GNOME settings", "Read the current controls in your own desktop session.", NULL, FALSE, FALSE, {"desktop", "status", NULL}},
    {"usb-list", "Refresh device list", "Refresh connected devices and their current authorization.", NULL, TRUE, FALSE, {"usb", "devices", NULL}},
    {"monitor-status", "System monitor status", "Inspect the privileged collector's service state.", NULL, TRUE, FALSE, {"monitor", "status", NULL}},
    {"monitor-logs", "Recent monitor events", "Read recent collector service output.", NULL, TRUE, FALSE, {"monitor", "logs", NULL}},
    {"monitor-disable", "Disable system monitoring", "Stop collecting new security-event notifications.", "Stop the OctoShield system monitor. Existing firewall, USB and other preventive controls remain configured, but monitoring will stop reporting new events.", TRUE, TRUE, {"monitor", "disable", NULL}},
    {"notify-enable", "Enable desktop notifications", "Receive security alerts in this user's GNOME session.", "Enable this user's notification service. The system collector must already be installed and running. GNOME notification preferences and Do Not Disturb can affect visibility.", FALSE, TRUE, {"monitor", "enable-desktop", NULL}},
    {"notify-disable", "Disable desktop notifications", "Stop notifications for this user without changing policy.", "Disable the notification service for this user. The system collector and preventive controls continue independently.", FALSE, TRUE, {"monitor", "disable-desktop", NULL}},
    {"notify-status", "Desktop notification status", "Inspect this user's notification service.", NULL, FALSE, FALSE, {"monitor", "status", NULL}},
    {"backups", "List configuration backups", "Show recorded system changes and recovery transactions.", NULL, TRUE, FALSE, {"backups", NULL}},
    {"recovery", "Read recovery guide", "Inspect the installed recovery and backup instructions.", NULL, FALSE, FALSE, {"recovery", NULL}},
    {"update-check", "Check for OctoShield updates", "Check the official GitHub release for a newer Debian package.", NULL, FALSE, FALSE, {"updates", "check", NULL}}
};

/* GNOME 46 and 50 ship this exact invocation in their Users desktop entry:
 * panels/system/users/gnome-users-panel.desktop.in. Users is a System subpage,
 * not the removed pre-46 user-accounts panel. Keep the executable path fixed. */
static const char *const accounts_argv[] = {
    "/usr/bin/gnome-control-center", "system", "users", NULL
};

typedef enum {
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
    GString *data_output;
    gchar *deferred_confirmation;
    guint64 last_prompt_id;
    guint64 current_prompt_id;
    guint64 deferred_prompt_id;
    gchar *answer;
    gboolean exited;
    gboolean exit_success;
    gboolean done_seen;
    gboolean reported_success;
    gboolean change_started_known;
    gboolean change_started;
    gboolean protocol_failed;
    gboolean waiting_confirmation;
    gboolean answer_pending;
    gboolean input_closed;
    gboolean review_truncated;
    gboolean data_seen;
    gboolean data_truncated;
    gboolean structured_data;
    gboolean session_operation;
    guint64 request_id;
};

struct Session {
    App *app;
    GSubprocess *process;
    GOutputStream *input;
    GInputStream *output;
    GByteArray *line;
    GQueue writes;
    gchar *writing;
    gboolean ready;
    gboolean closed;
    gboolean exited;
    gboolean eof;
    guint64 next_request;
};

struct App {
    AdwApplication *application;
    GtkWindow *window;
    AdwToastOverlay *toasts;
    GtkStack *pages;
    GtkListBox *navigation;
    AdwStyleManager *style_manager;
    GPtrArray *brand_pictures;
    gulong theme_handler;
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
    GPtrArray *status_rows;
    GPtrArray *profile_selectors;
    GPtrArray *profile_ids;
    GtkLabel *overview_title;
    GtkLabel *overview_summary;
    GtkLabel *checked_label;
    GtkLabel *usb_pending;
    GtkLabel *overview_usb;
    GtkLabel *profile_details;
    GtkLabel *update_status;
    GtkLinkButton *update_link;
    GtkDropDown *global_profile;
    GtkDropDown *edit_profile;
    GtkDropDown *access_profile;
    GtkDropDown *access_preset;
    GtkDropDown *access_scope;
    GtkDropDown *access_network;
    GtkDropDown *access_protocol;
    GtkDropDown *access_duration;
    GtkEditable *access_ports;
    GtkEditable *access_source;
    GtkEditable *access_interface;
    GtkWidget *access_custom;
    GtkWidget *access_address;
    GtkWidget *access_network_row;
    GtkListBox *access_rules;
    GtkLabel *access_summary;
    GtkLabel *access_editing;
    GtkButton *access_submit;
    gchar *access_edit_id;
    gchar *access_edit_profile;
    gchar *firewall_profile;
    gboolean access_profile_invalid;
    JsonArray *connection_data;
    GPtrArray *lan_options;
    GtkDropDown *privacy_connection;
    GtkDropDown *privacy_autoconnect;
    GtkDropDown *privacy_discovery;
    GtkDropDown *privacy_mac;
    GtkWidget *privacy_mac_row;
    GtkLabel *privacy_summary;
    GtkLabel *privacy_source;
    GtkLabel *diagnostics_title;
    GtkLabel *diagnostics_summary;
    GtkListBox *diagnostics_findings;
    JsonObject *container_plan;
    GtkWidget *container_apply;
    guint private_refresh;
    guint private_refresh_idle;
    gboolean access_loaded;
    gboolean connections_loaded;
    gboolean connections_incomplete;
    GtkListBox *usb_devices;
    GPtrArray *usb_inventory_rows;
    GHashTable *usb_decisions;
    AdwMessageDialog *usb_prompt;
    gchar *usb_profile;
    gchar *usb_inventory_signature;
    gboolean local_session_ready;
    gboolean auth_required;
    gboolean usb_review_launch;
    gboolean usb_automatic;
    gboolean shutting_down;
    Session *session;
    Request *pending_request;
    GtkStack *access_pages;
    GtkLabel *access_status;
    GtkButton *unlock;
    GtkButton *unlock_primary;
    GDBusProxy *login_session;
    GHashTable *setting_choices;
    gchar *active_profile;
    guint refresh_timer;
    gint64 status_not_before;
    gboolean cache_valid;
    gboolean usb_inventory;
    gboolean usb_cache_valid;
    gint64 usb_status_not_before;
    gboolean refresh_session_service;
    gboolean smoke_test;
};

static void operation_maybe_finish(Operation *operation);
static void update_actions(App *app);
static void read_next(Reader *reader);
static void show_confirmation(Operation *operation, guint64 id, const char *text);
static gboolean refresh_status(gpointer data);
static void handle_data_log(App *app, const char *text);
static void maybe_prompt_usb(App *app);
static void launch_request(Request *request);
static void session_unlock(App *app);
static void session_revoke(App *app, const char *reason);
static gboolean session_send(Session *session, JsonBuilder *builder);
static gboolean refresh_private(gpointer data);
static gboolean show_access(App *app, JsonObject *root);
static gboolean show_connections(App *app, JsonObject *root);
static gboolean show_diagnostics(App *app, JsonObject *root);
static gboolean show_container_plan(App *app, JsonObject *root);
static void review_status_clicked(GtkButton *button, gpointer data);
static void clear_list(GtkListBox *list);
static void access_cancel_edit(GtkButton *button, gpointer data);
static gboolean administrator_ready(App *app)
{
    return !app->auth_required || (app->session != NULL && app->session->ready && !app->session->closed);
}

static void reset_profile_choices(App *app)
{
    GHashTableIter iter;
    gpointer value;
    g_hash_table_iter_init(&iter, app->setting_choices);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        GListModel *model = gtk_drop_down_get_model(value);
        gtk_drop_down_set_selected(value, g_list_model_get_n_items(model) - 1);
    }
}

static const char *brand_resource(App *app)
{
    return adw_style_manager_get_dark(app->style_manager) ? BRAND_RESOURCE_DARK : BRAND_RESOURCE_LIGHT;
}

static void branding_changed(AdwStyleManager *manager, GParamSpec *property, gpointer data)
{
    (void)manager;
    (void)property;
    App *app = data;
    for (guint i = 0; i < app->brand_pictures->len; i++)
        gtk_picture_set_resource(g_ptr_array_index(app->brand_pictures, i), brand_resource(app));
}

static GtkWidget *brand_widget(App *app, int width, int height)
{
    OctoshieldBrand *brand = g_object_new(octoshield_brand_get_type(), NULL);
    brand->width = width;
    brand->height = height;
    gtk_widget_set_halign(GTK_WIDGET(brand), GTK_ALIGN_CENTER);
    gtk_widget_set_valign(GTK_WIDGET(brand), GTK_ALIGN_CENTER);
    gtk_picture_set_resource(GTK_PICTURE(brand->picture), brand_resource(app));
    g_ptr_array_add(app->brand_pictures, brand->picture);
    return GTK_WIDGET(brand);
}

static void branding_clear(App *app)
{
    if (app->refresh_timer != 0) {
        g_source_remove(app->refresh_timer);
        app->refresh_timer = 0;
    }
    g_clear_pointer(&app->status_rows, g_ptr_array_unref);
    g_clear_pointer(&app->profile_selectors, g_ptr_array_unref);
    g_clear_pointer(&app->profile_ids, g_ptr_array_unref);
    g_clear_pointer(&app->usb_inventory_rows, g_ptr_array_unref);
    g_clear_pointer(&app->usb_decisions, g_hash_table_unref);
    g_clear_pointer(&app->usb_profile, g_free);
    g_clear_pointer(&app->usb_inventory_signature, g_free);
    g_clear_pointer(&app->setting_choices, g_hash_table_unref);
    g_clear_pointer(&app->active_profile, g_free);
    if (app->private_refresh_idle != 0) g_source_remove(app->private_refresh_idle);
    app->private_refresh_idle = 0;
    g_clear_pointer(&app->firewall_profile, g_free);
    g_clear_pointer(&app->access_edit_id, g_free);
    g_clear_pointer(&app->access_edit_profile, g_free);
    g_clear_pointer(&app->connection_data, json_array_unref);
    g_clear_pointer(&app->lan_options, g_ptr_array_unref);
    g_clear_pointer(&app->container_plan, json_object_unref);
    if (app->theme_handler != 0) {
        g_signal_handler_disconnect(app->style_manager, app->theme_handler);
        app->theme_handler = 0;
    }
    g_clear_pointer(&app->brand_pictures, g_ptr_array_unref);
}

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
            if (!operation->session_operation) g_output_stream_close(operation->answers, NULL, NULL);
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
    if (operation->session_operation) session_revoke(operation->app, "The administrator connection was interrupted. Unlock to continue.");
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
    if (operation->input_closed && !operation->session_operation)
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
    if (operation->session_operation) {
        g_autoptr(JsonBuilder) builder = json_builder_new();
        json_builder_begin_object(builder);
        json_builder_set_member_name(builder, "type"); json_builder_add_string_value(builder, "answer");
        json_builder_set_member_name(builder, "request"); json_builder_add_int_value(builder, (gint64)operation->request_id);
        json_builder_set_member_name(builder, "id"); json_builder_add_int_value(builder, (gint64)operation->current_prompt_id);
        json_builder_set_member_name(builder, "allow"); json_builder_add_boolean_value(builder, accepted);
        json_builder_end_object(builder);
        if (!session_send(app->session, builder)) protocol_error(operation, "The administrator session is unavailable.");
    } else {
        operation->answer_pending = TRUE;
        operation->answer = g_strdup_printf("%" G_GUINT64_FORMAT " %s\n", operation->current_prompt_id, accepted ? "yes" : "no");
        g_output_stream_write_all_async(operation->answers, operation->answer, strlen(operation->answer), G_PRIORITY_DEFAULT,
                                       NULL, answer_written, operation);
    }
    gtk_label_set_text(app->activity, accepted ? "Applying the reviewed change…" : "Waiting for the helper after your decision…");
    update_actions(app);
}

static void show_confirmation(Operation *operation, guint64 id, const char *text)
{
    App *app = operation->app;
    operation->waiting_confirmation = TRUE;
    operation->current_prompt_id = id;
    gtk_label_set_text(app->activity, "Review required — the helper is waiting for your decision");
    GtkWidget *dialog = adw_message_dialog_new(app->window, "Confirm this change", "Check the proposed settings and their effect before applying them.");
    g_autofree gchar *review = g_strconcat(operation->review->str, "\nREQUEST\n", text, NULL);
    adw_message_dialog_set_extra_child(ADW_MESSAGE_DIALOG(dialog), plain_text_scroller(review));
    adw_message_dialog_add_responses(ADW_MESSAGE_DIALOG(dialog), "decline", "Cancel", "accept", "Apply change", NULL);
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
    case OCTOSHIELD_EVENT_DATA:
        if (operation->data_output == NULL || operation->data_seen || operation->data_output->len != 0) {
            protocol_error(operation, "Unexpected structured helper result.");
        } else {
            if (strlen(event.text) < MAX_REVIEW_BYTES) g_string_assign(operation->data_output, event.text);
            else operation->data_truncated = TRUE;
        }
        break;
    case OCTOSHIELD_EVENT_LOG:
        append_log(operation->app, event.text);
        if (operation->data_output != NULL && !operation->data_truncated && !operation->structured_data) {
            /* These three read-only commands emit JSON only. api::flush can
             * split either at a newline or after 4096 characters. JSON's raw
             * newlines are token whitespace, so concatenating preserves both
             * pretty-printed output and compact records split mid-string. */
            if (operation->data_output->len + strlen(event.text) < MAX_REVIEW_BYTES)
                g_string_append(operation->data_output, event.text);
            else operation->data_truncated = TRUE;
        }
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
        operation->change_started_known = event.change_started_known;
        operation->change_started = event.change_started;
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
    gboolean changed_access = g_str_equal(operation->title, "Allow network access") ||
        g_str_equal(operation->title, "Update network access") || g_str_equal(operation->title, "Revoke network access");
    gboolean changed_connection = g_str_equal(operation->title, "Save connection privacy") ||
        g_str_equal(operation->title, "Reconnect selected network") || g_str_equal(operation->title, "Review external network changes");
    gboolean changed_container = g_str_equal(operation->title, "Restrict container to this computer");
    if (!success) {
        app->private_refresh = 0;
        if (g_str_equal(operation->title, "Refresh access permissions")) gtk_label_set_text(app->access_summary, "Permission inspection failed. Read the operation details and refresh to retry.");
        if (g_str_equal(operation->title, "Refresh connections")) gtk_label_set_text(app->privacy_summary, "Connection inspection failed. Read the operation details and refresh to retry.");
        if (g_str_equal(operation->title, "Review protection details")) gtk_label_set_text(app->diagnostics_summary, "Inspection failed. Read the operation details; no conclusion was established.");
    }
    if (success && operation->data_output != NULL && !operation->data_truncated)
        handle_data_log(app, operation->data_output->str);
    if (success && operation->data_output != NULL && !operation->data_seen) {
        append_log(app, "The structured result could not be displayed safely. The textual operation details remain available; no previous view has been treated as a new result.");
        success = FALSE;
        app->private_refresh = 0;
    }
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
        if (operation->done_seen && !operation->reported_success &&
            !operation->protocol_failed && operation->change_started_known &&
            !operation->change_started) {
            gtk_label_set_text(app->activity, "Operation did not start — review the details");
            append_log(app, "No protection changes were started. Review the details above before retrying.");
        } else {
            gtk_label_set_text(app->activity, "Operation declined or failed — review the details");
            append_log(app, "Operation declined or failed. Earlier confirmed changes may still be in effect; consult Recovery before retrying.");
        }
        toast(app, "Review the operation details");
    }
    gtk_spinner_stop(app->spinner);
    gtk_widget_set_visible(GTK_WIDGET(app->spinner), FALSE);
    app->operation = NULL;
    g_byte_array_unref(operation->out.line);
    g_byte_array_unref(operation->err.line);
    g_clear_object(&operation->process);
    g_string_free(operation->review, TRUE);
    if (operation->data_output != NULL) g_string_free(operation->data_output, TRUE);
    g_free(operation->deferred_confirmation);
    g_free(operation->answer);
    if (!g_str_equal(operation->title, "Refresh device list")) app->usb_inventory = FALSE;
    g_free(operation->title);
    g_free(operation);
    update_actions(app);
    refresh_status(app);
    maybe_prompt_usb(app);
    if (changed_access && success) {
        access_cancel_edit(NULL, app);
        app->private_refresh |= 1U;
    }
    if (changed_connection) app->private_refresh |= 2U;
    if (changed_container && success) {
        gtk_label_set_text(app->diagnostics_summary, "This service's reviewed published host ports are now bound to localhost. Custom routing and firewall paths remain outside that verification. Keep the generated override in future deployments; the source files, recovery snapshot and command remain below.");
        if (app->container_apply != NULL) gtk_widget_set_sensitive(app->container_apply, FALSE);
        g_clear_pointer(&app->container_plan, json_object_unref);
    }
    if (changed_access && !success) {
        clear_list(app->access_rules); app->access_loaded = FALSE;
        gtk_label_set_text(app->access_summary, "The change did not complete. Read the operation details, then Refresh to verify the current permissions.");
    }
    if (changed_connection && !success) {
        app->connections_loaded = FALSE;
        gtk_label_set_text(app->privacy_summary, "The change did not complete. Refreshing actual saved and active settings; the operation details explain the failure.");
    }
    if (app->private_refresh != 0 && app->private_refresh_idle == 0 && !app->shutting_down)
        app->private_refresh_idle = g_idle_add(refresh_private, app);
    if (app->shutting_down) gtk_window_close(app->window);
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
    gboolean privileged = g_str_equal(request->argv[0], "/usr/bin/pkexec");
    gboolean session_operation = privileged && app->auth_required;
    if (session_operation && (!administrator_ready(app) || app->session->next_request >= G_MAXINT32)) {
        request_free(request);
        toast(app, "Unlock OctoShield before making changes");
        return;
    }
    g_autoptr(GError) error = NULL;
    GSubprocess *process = session_operation ? NULL : g_subprocess_newv((const gchar *const *)request->argv,
                                           G_SUBPROCESS_FLAGS_STDIN_PIPE |
                                           G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                                           G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
    if (!session_operation && process == NULL) {
        show_error(app, "Unable to start this operation", error->message);
        request_free(request);
        update_actions(app);
        return;
    }
    Operation *operation = g_new0(Operation, 1);
    operation->app = app;
    operation->process = process;
    operation->session_operation = session_operation;
    operation->answers = session_operation ? app->session->input : g_subprocess_get_stdin_pipe(process);
    operation->title = g_strdup(request->title);
    operation->review = g_string_new(NULL);
    if (g_str_equal(request->title, "Inspect profile configuration") ||
        g_str_equal(request->title, "Refresh device list") ||
        g_str_equal(request->title, "Check for OctoShield updates") ||
        g_str_equal(request->title, "Refresh access permissions") ||
        g_str_equal(request->title, "Refresh connections") ||
        g_str_equal(request->title, "Review protection details") ||
        g_str_equal(request->title, "Review container local access"))
        operation->data_output = g_string_new(NULL);
    operation->structured_data = g_str_equal(request->title, "Refresh access permissions") ||
        g_str_equal(request->title, "Refresh connections") || g_str_equal(request->title, "Review protection details") ||
        g_str_equal(request->title, "Review container local access");
    if (g_str_equal(request->title, "Refresh access permissions")) {
        app->access_loaded = FALSE; clear_list(app->access_rules);
        gtk_label_set_text(app->access_summary, "Inspecting saved and active permissions…");
    }
    if (g_str_equal(request->title, "Refresh connections")) {
        app->connections_loaded = FALSE;
        gtk_label_set_text(app->privacy_summary, "Inspecting saved and active connection settings…");
    }
    operation->out = (Reader){operation, session_operation ? NULL : g_subprocess_get_stdout_pipe(process), g_byte_array_new(), TRUE, FALSE, FALSE};
    operation->err = (Reader){operation, session_operation ? NULL : g_subprocess_get_stderr_pipe(process), g_byte_array_new(), FALSE, FALSE, FALSE};
    app->operation = operation;
    if (request->changes && g_str_equal(request->argv[0], "/usr/bin/pkexec")) {
        if (g_strcmp0(request->argv[2], "usb") == 0) app->usb_status_not_before = g_get_real_time() / G_USEC_PER_SEC;
        else app->status_not_before = g_get_real_time() / G_USEC_PER_SEC;
    }
    if (g_str_equal(request->title, "Inspect profile configuration")) {
        gtk_label_set_text(app->profile_details, "Loading the selected profile configuration…");
        reset_profile_choices(app);
    }
    gtk_text_buffer_set_text(app->log, "", 0);
    append_log(app, request->title);
    if (request->impact != NULL)
        append_log(app, request->impact);
    append_log(app, "Review this output and every requested confirmation. Closing this window does not interrupt a running system change.");
    gtk_expander_set_expanded(app->details, TRUE);
    gtk_label_set_text(app->activity, "Working — your administrator session is unlocked…");
    gtk_widget_set_visible(GTK_WIDGET(app->spinner), TRUE);
    gtk_spinner_start(app->spinner);
    update_actions(app);
    if (session_operation) {
        operation->request_id = ++app->session->next_request;
        g_autoptr(JsonBuilder) builder = json_builder_new();
        json_builder_begin_object(builder);
        json_builder_set_member_name(builder, "type"); json_builder_add_string_value(builder, "request");
        json_builder_set_member_name(builder, "id"); json_builder_add_int_value(builder, (gint64)operation->request_id);
        json_builder_set_member_name(builder, "args"); json_builder_begin_array(builder);
        for (guint i = 2; request->argv[i] != NULL; i++) json_builder_add_string_value(builder, request->argv[i]);
        json_builder_end_array(builder); json_builder_end_object(builder);
        if (!session_send(app->session, builder)) session_revoke(app, "Unable to submit the requested operation.");
    } else {
        read_next(&operation->out);
        read_next(&operation->err);
        g_subprocess_wait_async(process, NULL, process_waited, operation);
    }
    request_free(request);
}

static void session_maybe_finish(Session *session);
static void session_read_next(Session *session);

static void session_revoke(App *app, const char *reason)
{
    Session *session = app->session;
    if (session != NULL && !session->closed) {
        gboolean awaiting_authentication = !session->ready && session->next_request == 0 && !session->exited;
        session->closed = TRUE;
        session->ready = FALSE;
        /* EOF revokes this app's authority. The broker finishes only an already
         * confirmed mutation and denies every pending/future confirmation. */
        if (session->writing == NULL) g_output_stream_close(session->input, NULL, NULL);
        /* pkexec does not consume this pipe while its authentication dialog is
         * pending. End that request too, but only before READY and before any
         * command could have been issued. Never signal an authorized operation.
         * If authorization raced ahead, the unused broker still sees EOF. */
        if (awaiting_authentication && session->process != NULL)
            g_subprocess_send_signal(session->process, SIGTERM);
    }
    if (app->operation != NULL) {
        close_answers(app->operation);
        app->operation->waiting_confirmation = FALSE;
        g_clear_pointer(&app->operation->deferred_confirmation, g_free);
        if (app->confirmation != NULL) {
            AdwMessageDialog *dialog = app->confirmation;
            app->confirmation = NULL;
            adw_message_dialog_response(dialog, "decline");
        }
    }
    if (app->shutting_down) {
        if (app->pending_request != NULL) { request_free(app->pending_request); app->pending_request = NULL; }
        return;
    }
    if (app->access_status != NULL) gtk_label_set_text(app->access_status, reason);
    app->access_loaded = FALSE; app->connections_loaded = FALSE; app->private_refresh = 0;
    if (app->access_rules != NULL) clear_list(app->access_rules);
    if (app->access_editing != NULL) access_cancel_edit(NULL, app);
    g_clear_pointer(&app->container_plan, json_object_unref);
    if (app->container_apply != NULL) gtk_widget_set_sensitive(app->container_apply, FALSE);
    if (app->usb_prompt != NULL) adw_message_dialog_response(app->usb_prompt, "block");
    if (app->pending_request != NULL) { request_free(app->pending_request); app->pending_request = NULL; }
    update_actions(app);
}

static void session_write_next(Session *session);

static void session_written(GObject *source, GAsyncResult *result, gpointer data)
{
    Session *session = data;
    g_autoptr(GError) error = NULL;
    if (!g_output_stream_write_all_finish(G_OUTPUT_STREAM(source), result, NULL, &error))
        session_revoke(session->app, "The administrator connection closed. Unlock to continue.");
    g_clear_pointer(&session->writing, g_free);
    if (session->closed) {
        g_queue_clear_full(&session->writes, g_free);
        g_output_stream_close(session->input, NULL, NULL);
    } else session_write_next(session);
    session_maybe_finish(session);
}

static void session_write_next(Session *session)
{
    if (session->closed || session->writing != NULL || g_queue_is_empty(&session->writes)) return;
    session->writing = g_queue_pop_head(&session->writes);
    g_output_stream_write_all_async(session->input, session->writing, strlen(session->writing),
                                   G_PRIORITY_DEFAULT, NULL, session_written, session);
}

static gboolean session_send(Session *session, JsonBuilder *builder)
{
    if (session == NULL || !session->ready || session->closed || session->writes.length >= 4) return FALSE;
    g_autoptr(JsonNode) node = json_builder_get_root(builder);
    g_autoptr(JsonGenerator) generator = json_generator_new();
    json_generator_set_root(generator, node);
    g_autofree gchar *json = json_generator_to_data(generator, NULL);
    g_queue_push_tail(&session->writes, g_strconcat(json, "\n", NULL));
    session_write_next(session);
    return TRUE;
}

static gboolean session_integer(JsonObject *object, const char *name, gint64 *number)
{
    JsonNode *node = json_object_get_member(object, name);
    if (node == NULL || !JSON_NODE_HOLDS_VALUE(node) || json_node_get_value_type(node) != G_TYPE_INT64) return FALSE;
    *number = json_node_get_int(node);
    return TRUE;
}

static void session_event(Session *session)
{
    App *app = session->app;
    g_autoptr(JsonParser) parser = json_parser_new();
    if (session->line->len == 0 || memchr(session->line->data, '\0', session->line->len) != NULL ||
        !json_parser_load_from_data(parser, (const char *)session->line->data, session->line->len, NULL)) {
        session_revoke(app, "Invalid administrator response. Unlock to start a new session."); return;
    }
    JsonNode *node = json_parser_get_root(parser);
    if (!JSON_NODE_HOLDS_OBJECT(node)) { session_revoke(app, "Invalid administrator response."); return; }
    JsonObject *object = json_node_get_object(node);
    JsonNode *type_node = json_object_get_member(object, "type");
    if (type_node == NULL || !JSON_NODE_HOLDS_VALUE(type_node) || json_node_get_value_type(type_node) != G_TYPE_STRING) {
        session_revoke(app, "Invalid administrator response."); return;
    }
    const char *type = json_node_get_string(type_node);
    if (g_str_equal(type, "ready")) {
        if (session->ready || session->closed) { session_revoke(app, "Unexpected administrator response."); return; }
        session->ready = TRUE;
        app->usb_review_launch = FALSE;
        app->local_session_ready = TRUE; /* Broker independently verified logind. */
        if (app->access_status != NULL) gtk_label_set_text(app->access_status, "Administrator session unlocked. Lock or close OctoShield to end it.");
        const char *page = gtk_stack_get_visible_child_name(app->pages);
        if (g_strcmp0(page, "office") == 0) app->private_refresh |= 3U;
        if (g_strcmp0(page, "privacy") == 0) app->private_refresh |= 2U;
        update_actions(app);
        if (app->pending_request != NULL) {
            Request *request = app->pending_request; app->pending_request = NULL;
            launch_request(request);
        } else maybe_prompt_usb(app);
        return;
    }
    if (g_str_equal(type, "closed")) {
        session_revoke(app, "Administrator access ended. Unlock to continue. Devices remain protected by the current policy."); return;
    }
    gint64 request = 0;
    Operation *operation = app->operation;
    if (!session->ready || !session_integer(object, "request", &request) || request < 1 ||
        operation == NULL || !operation->session_operation || (guint64)request != operation->request_id) {
        session_revoke(app, "An administrator response did not match the active operation."); return;
    }
    if (g_str_equal(type, "finished")) {
        gint64 exit_code = -1;
        if (!session_integer(object, "exit_code", &exit_code) || exit_code < 0 || exit_code > 255) {
            session_revoke(app, "Invalid administrator completion result."); return;
        }
        operation->exited = TRUE;
        operation->exit_success = exit_code == 0;
        operation->out.eof = operation->err.eof = TRUE;
        operation_maybe_finish(operation);
        return;
    }
    if (g_str_equal(type, "stderr")) {
        JsonNode *text = json_object_get_member(object, "text");
        if (text != NULL && JSON_NODE_HOLDS_VALUE(text) && json_node_get_value_type(text) == G_TYPE_STRING) {
            g_autofree gchar *safe = octoshield_text_sanitize(json_node_get_string(text), -1);
            append_log(app, safe);
        } else session_revoke(app, "Invalid administrator diagnostic output.");
        return;
    }
    g_byte_array_set_size(operation->out.line, 0);
    g_byte_array_append(operation->out.line, session->line->data, session->line->len);
    handle_line(&operation->out);
    g_byte_array_set_size(operation->out.line, 0);
}

static void session_read(GObject *source, GAsyncResult *result, gpointer data)
{
    Session *session = data;
    g_autoptr(GBytes) bytes = g_input_stream_read_bytes_finish(G_INPUT_STREAM(source), result, NULL);
    if (bytes == NULL || g_bytes_get_size(bytes) == 0) {
        session->eof = TRUE;
        session_revoke(session->app, "OctoShield is locked. Unlock with an administrator account to continue.");
        session_maybe_finish(session);
        return;
    }
    gsize size = 0;
    const guint8 *buffer = g_bytes_get_data(bytes, &size);
    for (gsize i = 0; i < size; i++) {
        if (buffer[i] == '\n') {
            if (!session->closed) session_event(session);
            g_byte_array_set_size(session->line, 0);
        } else if (!session->closed) {
            if (session->line->len >= MAX_PROTOCOL_LINE)
                session_revoke(session->app, "An administrator response exceeded its safety limit.");
            else g_byte_array_append(session->line, &buffer[i], 1);
        }
    }
    session_read_next(session);
}

static void session_read_next(Session *session)
{
    g_input_stream_read_bytes_async(session->output, 4096, G_PRIORITY_DEFAULT, NULL, session_read, session);
}

static void session_maybe_finish(Session *session)
{
    if (!session->exited || !session->eof || session->writing != NULL) return;
    App *app = session->app;
    if (app->session == session) app->session = NULL;
    if (app->operation != NULL && app->operation->session_operation) {
        Operation *operation = app->operation;
        operation->protocol_failed = TRUE;
        operation->exited = TRUE;
        operation->out.eof = operation->err.eof = TRUE;
        operation_maybe_finish(operation);
    }
    g_queue_clear_full(&session->writes, g_free);
    g_byte_array_unref(session->line);
    g_object_unref(session->process);
    g_free(session);
    if (!app->shutting_down) { update_actions(app); maybe_prompt_usb(app); }
}

static void session_waited(GObject *source, GAsyncResult *result, gpointer data)
{
    Session *session = data;
    g_subprocess_wait_finish(G_SUBPROCESS(source), result, NULL);
    session->exited = TRUE;
    session_maybe_finish(session);
}

static void session_unlock(App *app)
{
    if (app->smoke_test || app->shutting_down || app->session != NULL) return;
    const char *const argv[] = {"/usr/bin/pkexec", "--disable-internal-agent", "/usr/libexec/octoshield-session", NULL};
    g_autoptr(GError) error = NULL;
    GSubprocess *process = g_subprocess_newv(argv, G_SUBPROCESS_FLAGS_STDIN_PIPE |
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE, &error);
    if (process == NULL) { show_error(app, "Unable to unlock OctoShield", error->message); return; }
    Session *session = g_new0(Session, 1);
    session->app = app; session->process = process;
    session->input = g_subprocess_get_stdin_pipe(process);
    session->output = g_subprocess_get_stdout_pipe(process);
    session->line = g_byte_array_new();
    app->session = session;
    gtk_label_set_text(app->access_status, "Choose an administrator account in the system authentication dialog. OctoShield never receives or stores its password.");
    session_read_next(session);
    g_subprocess_wait_async(process, NULL, session_waited, session);
    update_actions(app);
}

static void unlock_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    if (app->session != NULL && !app->session->closed) session_revoke(app, "OctoShield is locked. Unlock to begin a new administrator session.");
    else session_unlock(app);
}

static gboolean login_boolean(GDBusProxy *proxy, const char *name)
{
    g_autoptr(GVariant) value = g_dbus_proxy_get_cached_property(proxy, name);
    return value != NULL && g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN) && g_variant_get_boolean(value);
}

static void login_changed(GDBusProxy *proxy, GVariant *changed, const gchar *const *invalidated, gpointer data)
{
    (void)changed; (void)invalidated;
    App *app = data;
    if (app->shutting_down) return;
    g_autoptr(GVariant) remote = g_dbus_proxy_get_cached_property(proxy, "Remote");
    g_autoptr(GVariant) locked = g_dbus_proxy_get_cached_property(proxy, "LockedHint");
    g_autoptr(GVariant) type = g_dbus_proxy_get_cached_property(proxy, "Type");
    g_autoptr(GVariant) user = g_dbus_proxy_get_cached_property(proxy, "User");
    guint uid = G_MAXUINT;
    if (user != NULL && g_variant_is_of_type(user, G_VARIANT_TYPE("(uo)"))) g_variant_get_child(user, 0, "u", &uid);
    g_autofree gchar *owner = g_dbus_proxy_get_name_owner(proxy);
    app->local_session_ready = owner != NULL && remote != NULL && locked != NULL && type != NULL &&
        g_variant_is_of_type(remote, G_VARIANT_TYPE_BOOLEAN) && g_variant_is_of_type(locked, G_VARIANT_TYPE_BOOLEAN) &&
        g_variant_is_of_type(type, G_VARIANT_TYPE_STRING) && login_boolean(proxy, "Active") &&
        !g_variant_get_boolean(remote) && !g_variant_get_boolean(locked) && uid == getuid() &&
        (g_str_equal(g_variant_get_string(type, NULL), "wayland") || g_str_equal(g_variant_get_string(type, NULL), "x11"));
    if (!app->local_session_ready) session_revoke(app, "Your desktop session is inactive or locked. Unlock OctoShield after returning.");
    else maybe_prompt_usb(app);
}

static void login_owner_changed(GObject *object, GParamSpec *property, gpointer data)
{
    (void)property;
    login_changed(G_DBUS_PROXY(object), NULL, NULL, data);
}

static void login_proxy_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    (void)source;
    App *app = data;
    app->login_session = g_dbus_proxy_new_for_bus_finish(result, NULL);
    if (app->login_session == NULL) return;
    if (app->shutting_down) { g_clear_object(&app->login_session); return; }
    g_signal_connect(app->login_session, "g-properties-changed", G_CALLBACK(login_changed), app);
    g_signal_connect(app->login_session, "notify::g-name-owner", G_CALLBACK(login_owner_changed), app);
    login_changed(app->login_session, NULL, NULL, app);
}

typedef struct {
    App *app;
    GDBusConnection *connection;
    GPtrArray *matches;
    guint pending;
    gboolean failed;
} LoginDiscovery;

typedef struct {
    LoginDiscovery *discovery;
    gchar *path;
} LoginCandidate;

static gboolean login_properties_readable(GVariant *properties)
{
    gboolean active, remote, locked;
    const char *type, *path;
    guint uid;
    return g_variant_lookup(properties, "Active", "b", &active) &&
        g_variant_lookup(properties, "Remote", "b", &remote) &&
        g_variant_lookup(properties, "LockedHint", "b", &locked) &&
        g_variant_lookup(properties, "Type", "&s", &type) &&
        g_variant_lookup(properties, "User", "(u&o)", &uid, &path);
}

static gboolean login_properties_eligible(GVariant *properties)
{
    gboolean active = FALSE, remote = TRUE, locked = TRUE;
    const char *type = NULL, *user_path = NULL;
    guint uid = G_MAXUINT;
    return g_variant_lookup(properties, "Active", "b", &active) && active &&
        g_variant_lookup(properties, "Remote", "b", &remote) && !remote &&
        g_variant_lookup(properties, "LockedHint", "b", &locked) && !locked &&
        g_variant_lookup(properties, "Type", "&s", &type) &&
        (g_str_equal(type, "wayland") || g_str_equal(type, "x11")) &&
        g_variant_lookup(properties, "User", "(u&o)", &uid, &user_path) && uid == getuid();
}

static void login_candidate_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    LoginCandidate *candidate = data;
    LoginDiscovery *discovery = candidate->discovery;
    g_autoptr(GVariant) response = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, NULL);
    if (response != NULL) {
        g_autoptr(GVariant) properties = NULL;
        g_variant_get(response, "(@a{sv})", &properties);
        if (!login_properties_readable(properties)) discovery->failed = TRUE;
        else if (login_properties_eligible(properties)) g_ptr_array_add(discovery->matches, g_strdup(candidate->path));
    } else discovery->failed = TRUE;
    g_free(candidate->path); g_free(candidate);
    if (--discovery->pending != 0) return;
    if (!discovery->failed && discovery->matches->len == 1 && !discovery->app->shutting_down)
        g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
            NULL, "org.freedesktop.login1", g_ptr_array_index(discovery->matches, 0),
            "org.freedesktop.login1.Session", NULL, login_proxy_ready, discovery->app);
    g_ptr_array_unref(discovery->matches);
    g_object_unref(discovery->connection);
    g_free(discovery);
}

static void login_sessions_listed(GObject *source, GAsyncResult *result, gpointer data)
{
    App *app = data;
    g_autoptr(GVariant) response = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, NULL);
    if (response == NULL || app->shutting_down) return;
    g_autoptr(GVariant) sessions = NULL;
    g_variant_get(response, "(@a(susso))", &sessions);
    if (g_variant_n_children(sessions) > 128) return;
    LoginDiscovery *discovery = g_new0(LoginDiscovery, 1);
    discovery->app = app;
    discovery->connection = G_DBUS_CONNECTION(g_object_ref(source));
    discovery->matches = g_ptr_array_new_with_free_func(g_free);
    GVariantIter iterator;
    g_variant_iter_init(&iterator, sessions);
    const char *id, *user, *seat, *path;
    guint uid;
    while (g_variant_iter_next(&iterator, "(&su&s&s&o)", &id, &uid, &user, &seat, &path)) {
        if (uid != getuid()) continue;
        LoginCandidate *candidate = g_new0(LoginCandidate, 1);
        candidate->discovery = discovery; candidate->path = g_strdup(path);
        discovery->pending++;
        g_dbus_connection_call(discovery->connection, "org.freedesktop.login1", path,
            "org.freedesktop.DBus.Properties", "GetAll", g_variant_new("(s)", "org.freedesktop.login1.Session"),
            G_VARIANT_TYPE("(a{sv})"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 1500, NULL, login_candidate_ready, candidate);
    }
    if (discovery->pending == 0) {
        g_ptr_array_unref(discovery->matches); g_object_unref(discovery->connection); g_free(discovery);
    }
}

static void login_session_found(GObject *source, GAsyncResult *result, gpointer data)
{
    App *app = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) response = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (response == NULL) {
        g_autofree gchar *remote = error != NULL ? g_dbus_error_get_remote_error(error) : NULL;
        if (g_strcmp0(remote, "org.freedesktop.login1.NoSessionForPID") == 0)
            g_dbus_connection_call(G_DBUS_CONNECTION(source), "org.freedesktop.login1", "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager", "ListSessions", NULL, G_VARIANT_TYPE("(a(susso))"),
                G_DBUS_CALL_FLAGS_NO_AUTO_START, 1500, NULL, login_sessions_listed, app);
        return;
    }
    const char *path = NULL;
    g_variant_get(response, "(&o)", &path);
    g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
        NULL, "org.freedesktop.login1", path, "org.freedesktop.login1.Session", NULL, login_proxy_ready, app);
}

static void login_bus_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    (void)source;
    g_autoptr(GDBusConnection) connection = g_bus_get_finish(result, NULL);
    if (connection == NULL || ((App *)data)->shutting_down) return;
    g_dbus_connection_call(connection, "org.freedesktop.login1", "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager", "GetSessionByPID", g_variant_new("(u)", (guint)getpid()),
        G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 1500, NULL, login_session_found, data);
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
    if (!administrator_ready(app)) {
        if (app->pending_request != NULL) request_free(app->pending_request);
        app->pending_request = request;
        session_unlock(app);
        return;
    }
    /* Privileged helpers present their actual plan before mutation. A second
     * generic desktop confirmation adds no evidence and obscures that plan. */
    if (!changes || privileged) {
        launch_request(request);
        return;
    }
    GtkWidget *dialog = adw_message_dialog_new(app->window, title, impact);
    adw_message_dialog_add_responses(ADW_MESSAGE_DIALOG(dialog), "cancel", "Cancel", "continue", "Apply", NULL);
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
    gboolean enabled = administrator_ready(app) && app->operation == NULL && app->preview == NULL && app->usb_prompt == NULL && !app->smoke_test;
    for (guint i = 0; i < app->operation_widgets->len; i++)
        gtk_widget_set_sensitive(g_ptr_array_index(app->operation_widgets, i), enabled);
    gtk_widget_set_visible(app->decline, app->operation != NULL && app->operation->waiting_confirmation);
    if (app->usb_devices != NULL) gtk_widget_set_sensitive(GTK_WIDGET(app->usb_devices), enabled);
    if (app->access_rules != NULL) gtk_widget_set_sensitive(GTK_WIDGET(app->access_rules), enabled);
    if (app->diagnostics_findings != NULL) gtk_widget_set_sensitive(GTK_WIDGET(app->diagnostics_findings), enabled);
    if (app->access_pages != NULL) gtk_stack_set_visible_child_name(app->access_pages, administrator_ready(app) || app->smoke_test ? "application" : "locked");
    gboolean authenticating = app->session != NULL && !app->session->closed && !app->session->ready;
    gboolean available = !app->smoke_test && (app->session == NULL || !app->session->closed);
    if (app->unlock != NULL) {
        gtk_button_set_label(app->unlock, authenticating ? "Cancel authentication" : administrator_ready(app) ? "Lock" : available ? "Unlock" : "Locking…");
        gtk_widget_set_sensitive(GTK_WIDGET(app->unlock), available);
    }
    if (app->unlock_primary != NULL) {
        gtk_button_set_label(app->unlock_primary, authenticating ? "Cancel authentication" : "Unlock with an administrator account");
        gtk_widget_set_sensitive(GTK_WIDGET(app->unlock_primary), available);
    }
    if (enabled && app->private_refresh != 0 && app->private_refresh_idle == 0 && !app->shutting_down)
        app->private_refresh_idle = g_idle_add(refresh_private, app);
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
    /* Adwaita renders group headings and descriptions as markup internally,
     * unlike our explicitly plain-text action rows. Escape every value here
     * so punctuation and future dynamic descriptions remain literal text. */
    g_autofree gchar *safe_title = g_markup_escape_text(title, -1);
    adw_preferences_group_set_title(ADW_PREFERENCES_GROUP(group), safe_title);
    if (description != NULL) {
        g_autofree gchar *safe_description = g_markup_escape_text(description, -1);
        adw_preferences_group_set_description(ADW_PREFERENCES_GROUP(group), safe_description);
    }
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

static void choice_label_setup(GtkSignalListItemFactory *factory, GtkListItem *item, gpointer data)
{
    (void)factory; (void)data;
    GtkWidget *label = gtk_label_new(NULL);
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(label), 28);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_list_item_set_child(item, label);
}

static void choice_label_bind(GtkSignalListItemFactory *factory, GtkListItem *item, gpointer data)
{
    (void)factory; (void)data;
    GtkStringObject *object = GTK_STRING_OBJECT(gtk_list_item_get_item(item));
    GtkWidget *label = gtk_list_item_get_child(item);
    gtk_label_set_text(GTK_LABEL(label), gtk_string_object_get_string(object));
    gtk_widget_set_tooltip_text(label, gtk_string_object_get_string(object));
}

static void bound_dropdown(GtkDropDown *choice)
{
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();
    g_signal_connect(factory, "setup", G_CALLBACK(choice_label_setup), NULL);
    g_signal_connect(factory, "bind", G_CALLBACK(choice_label_bind), NULL);
    gtk_drop_down_set_factory(choice, factory); gtk_drop_down_set_list_factory(choice, factory);
    g_object_unref(factory);
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
    GSubprocess *process = g_subprocess_newv(accounts_argv, G_SUBPROCESS_FLAGS_NONE, &error);
    if (process == NULL)
        show_error(app, "Unable to open GNOME Accounts", error->message);
    else
        g_subprocess_wait_async(process, NULL, accounts_waited, NULL);
}

static GtkWidget *about_window(App *app)
{
    static const char *developers[] = {"Vast Development Method", NULL};
    GtkWidget *about = adw_about_window_new();
    gtk_window_set_transient_for(GTK_WINDOW(about), app->window);
    gtk_window_set_modal(GTK_WINDOW(about), TRUE);
    adw_about_window_set_application_name(ADW_ABOUT_WINDOW(about), "OctoShield");
    adw_about_window_set_application_icon(ADW_ABOUT_WINDOW(about), OCTOSHIELD_APPLICATION_ID);
    adw_about_window_set_developer_name(ADW_ABOUT_WINDOW(about), "Vast Development Method");
    adw_about_window_set_developers(ADW_ABOUT_WINDOW(about), developers);
    adw_about_window_set_version(ADW_ABOUT_WINDOW(about), OCTOSHIELD_VERSION);
    adw_about_window_set_website(ADW_ABOUT_WINDOW(about), "https://www.vdm.io");
    adw_about_window_set_comments(ADW_ABOUT_WINDOW(about), "Laptop protection for Ubuntu and GNOME.\nPart of the Octoleo suite.");
    adw_about_window_set_license_type(ADW_ABOUT_WINDOW(about), GTK_LICENSE_APACHE_2_0);
    adw_about_window_set_copyright(ADW_ABOUT_WINDOW(about), "© 2026 Vast Development Method");
    return about;
}

static void about_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    gtk_window_present(GTK_WINDOW(about_window(data)));
}

typedef struct {
    const char *section;
    const char *key;
    AdwActionRow *row;
    GtkLabel *badge;
    GtkImage *icon;
} StatusRow;

typedef enum {
    PROFILE_APPLY, PROFILE_RESTORE, PROFILE_CREATE, PROFILE_DELETE,
    PROFILE_SHOW, PROFILE_SET, PROFILE_RULE_ADD, PROFILE_RULE_REMOVE, PROFILE_ENROLL
} ProfileCommand;

typedef struct {
    App *app;
    ProfileCommand command;
    const char *control;
    const char *key;
    GtkDropDown *profile;
    GtkDropDown *choice;
    GtkEditable *fields[5];
} ProfileBinding;

static JsonObject *object_member(JsonObject *object, const char *name)
{
    JsonNode *node = object != NULL ? json_object_get_member(object, name) : NULL;
    return node != NULL && JSON_NODE_HOLDS_OBJECT(node) ? json_node_get_object(node) : NULL;
}

static const char *string_member(JsonObject *object, const char *name, const char *fallback)
{
    JsonNode *node = object != NULL ? json_object_get_member(object, name) : NULL;
    return node != NULL && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == G_TYPE_STRING ? json_node_get_string(node) : fallback;
}

static JsonArray *array_member(JsonObject *object, const char *name)
{
    JsonNode *node = object != NULL ? json_object_get_member(object, name) : NULL;
    return node != NULL && JSON_NODE_HOLDS_ARRAY(node) ? json_node_get_array(node) : NULL;
}

static const char *selected_profile(App *app, GtkDropDown *selector)
{
    guint index = gtk_drop_down_get_selected(selector);
    return index < app->profile_ids->len ? g_ptr_array_index(app->profile_ids, index) : NULL;
}

static GtkWidget *profile_selector(App *app)
{
    GtkStringList *model = gtk_string_list_new(NULL);
    for (guint i = 0; i < app->profile_ids->len; i++)
        gtk_string_list_append(model, g_ptr_array_index(app->profile_ids, i));
    GtkWidget *selector = gtk_drop_down_new(G_LIST_MODEL(model), NULL);
    gtk_widget_set_size_request(selector, 125, -1);
    g_ptr_array_add(app->profile_selectors, selector);
    g_ptr_array_add(app->operation_widgets, selector);
    return selector;
}

static void profile_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    ProfileBinding *binding = data;
    App *app = binding->app;
    const char *profile = binding->profile != NULL ? selected_profile(app, binding->profile) : NULL;
    const char *args[8] = {"profile", NULL};
    const char *title = "Apply profile";
    const char *impact = "The helper will show the exact changes and ask before applying them. Profile changes can disconnect devices and network services.";
    gsize count = 0;
    gboolean changes = TRUE;
    if (binding->profile != NULL && profile == NULL)
        return;
    switch (binding->command) {
    case PROFILE_APPLY:
        args[1] = "apply"; args[2] = profile; count = 3;
        if (binding->control != NULL) { args[3] = binding->control; count = 4; }
        break;
    case PROFILE_RESTORE:
        args[1] = "restore"; count = 2; title = "Restore previous system settings";
        if (binding->control != NULL) { args[2] = binding->control; count = 3; }
        break;
    case PROFILE_CREATE:
        args[1] = "create"; args[2] = gtk_editable_get_text(binding->fields[0]); args[3] = profile; count = 4;
        title = "Create a profile"; impact = "Copy this profile's settings and remembered USB permissions to a new name. The original profile remains unchanged. Apply the new profile when you are ready.";
        break;
    case PROFILE_DELETE:
        args[1] = "delete"; args[2] = profile; count = 3; title = "Delete this profile";
        break;
    case PROFILE_SHOW:
        args[1] = "show"; args[2] = profile; count = 3; title = "Inspect profile configuration"; changes = FALSE;
        break;
    case PROFILE_SET: {
        static const char *const service_values[] = {"enabled", "disabled", "baseline"};
        static const char *const boolean_values[] = {"true", "false"};
        guint index = gtk_drop_down_get_selected(binding->choice);
        gboolean service = g_str_has_prefix(binding->key, "services.");
        if (index >= (service ? 3U : 2U)) return;
        args[1] = "set"; args[2] = profile; args[3] = binding->key;
        args[4] = service ? service_values[index] : boolean_values[index]; count = 5;
        title = "Save profile setting"; impact = "This edits the saved profile. Use Apply to activate its new settings.";
        break;
    }
    case PROFILE_RULE_ADD:
        args[1] = "rule-add"; args[2] = profile; args[3] = gtk_editable_get_text(binding->fields[0]);
        args[4] = gtk_drop_down_get_selected(binding->choice) == 0 ? "tcp" : "udp";
        args[5] = gtk_editable_get_text(binding->fields[1]); args[6] = gtk_editable_get_text(binding->fields[2]);
        args[7] = gtk_editable_get_text(binding->fields[3]); count = 8;
        title = "Save firewall exception"; impact = "Save this incoming exception, then apply the selected firewall profile. Temporary rules expire at their deadline or earlier when the firewall reloads or the machine restarts. A source of any permits every source; prefer a trusted address or subnet.";
        break;
    case PROFILE_RULE_REMOVE:
        args[1] = "rule-remove"; args[2] = profile; args[3] = gtk_editable_get_text(binding->fields[0]); count = 4;
        title = "Remove firewall exception"; impact = "Remove the saved exception. Apply this firewall profile to update the active rules.";
        break;
    case PROFILE_ENROLL:
        args[0] = "usb"; args[1] = "enroll"; args[2] = profile; count = 3;
        title = "Prepare trusted USB devices for this profile";
        impact = "Disconnect untrusted devices. Review every connected device before remembering the set for this profile.";
        break;
    }
    start_action(app, title, impact, TRUE, changes, count, args);
}

static GtkWidget *profile_button(App *app, const char *label, ProfileCommand command,
                                 GtkDropDown *profile, const char *control, const char *key,
                                 GtkDropDown *choice, GtkWidget **fields)
{
    GtkWidget *button = gtk_button_new_with_label(label);
    gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
    ProfileBinding *binding = g_new0(ProfileBinding, 1);
    binding->app = app; binding->command = command; binding->profile = profile;
    binding->control = control; binding->key = key; binding->choice = choice;
    for (guint i = 0; fields != NULL && i < 5 && fields[i] != NULL; i++)
        binding->fields[i] = GTK_EDITABLE(fields[i]);
    g_object_set_data_full(G_OBJECT(button), "profile-binding", binding, g_free);
    g_signal_connect(button, "clicked", G_CALLBACK(profile_clicked), binding);
    g_ptr_array_add(app->operation_widgets, button);
    return button;
}

static GtkWidget *status_row(App *app, const char *section, const char *key, const char *title)
{
    StatusRow *binding = g_new0(StatusRow, 1);
    binding->section = section; binding->key = key;
    binding->row = ADW_ACTION_ROW(adw_action_row_new());
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(binding->row), title);
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(binding->row), FALSE);
    adw_action_row_set_subtitle(binding->row, "Waiting for a current system observation");
    adw_action_row_set_subtitle_lines(binding->row, 3);
    binding->badge = GTK_LABEL(gtk_label_new("Unknown"));
    binding->icon = GTK_IMAGE(gtk_image_new_from_icon_name("dialog-question-symbolic"));
    adw_action_row_add_prefix(binding->row, GTK_WIDGET(binding->icon));
    adw_action_row_add_suffix(binding->row, GTK_WIDGET(binding->badge));
    if (g_str_equal(key, "firewall") || g_str_equal(key, "network") ||
        g_str_equal(key, "disk_encryption") || g_str_equal(key, "containers") || g_str_equal(key, "forwarding")) {
        GtkWidget *review = gtk_button_new_with_label(g_str_equal(key, "firewall") || g_str_equal(key, "network") ? "Manage" : "Review");
        gtk_widget_set_valign(review, GTK_ALIGN_CENTER);
        g_object_set_data(G_OBJECT(review), "topic", (gpointer)key);
        g_signal_connect(review, "clicked", G_CALLBACK(review_status_clicked), app);
        g_ptr_array_add(app->operation_widgets, review);
        adw_action_row_add_suffix(binding->row, review);
        adw_action_row_set_activatable_widget(binding->row, review);
    }
    g_ptr_array_add(app->status_rows, binding);
    return GTK_WIDGET(binding->row);
}

static void update_status_row(StatusRow *row, JsonObject *root)
{
    JsonObject *data = object_member(object_member(root, row->section), row->key);
    const char *state = string_member(data, "state", "unknown");
    JsonObject *profile_state = object_member(root, "profiles");
    JsonNode *available = profile_state != NULL ? json_object_get_member(profile_state, "available") : NULL;
    const char *result = string_member(object_member(object_member(object_member(root, "profiles"), "results"), row->key), "status", "");
    if (g_str_equal(row->section, "controls") && (g_str_equal(result, "failed") || g_str_equal(result, "pending") || g_str_equal(result, "applying")))
        state = "partial";
    gboolean managed = g_str_equal(row->section, "controls") && (g_str_equal(row->key, "firewall") || g_str_equal(row->key, "usb") || g_str_equal(row->key, "network") || g_str_equal(row->key, "services") || g_str_equal(row->key, "monitor"));
    if (managed && available != NULL && JSON_NODE_HOLDS_VALUE(available) && json_node_get_value_type(available) == G_TYPE_BOOLEAN && !json_node_get_boolean(available))
        state = "unknown";
    const char *label = "Unknown";
    const char *icon = "dialog-question-symbolic";
    const char *css = "dim-label";
    if (g_str_equal(state, "active")) { label = "Active"; icon = "object-select-symbolic"; css = "success"; }
    else if (g_str_equal(state, "inactive")) { label = "Inactive"; icon = "media-playback-stop-symbolic"; css = "warning"; }
    else if (g_str_equal(state, "partial")) { label = "Needs attention"; icon = "dialog-warning-symbolic"; css = "warning"; }
    else if (g_str_equal(state, "unsupported")) { label = "Not available"; icon = "dialog-information-symbolic"; }
    if (g_str_equal(state, "active") && g_str_equal(row->key, "disk_encryption")) label = "Encryption detected";
    if (g_str_equal(state, "active") && g_str_equal(row->key, "containers")) label = "Bindings inspected";
    if (g_str_equal(state, "unknown") && g_str_equal(row->key, "forwarding")) label = "Review routing";
    gtk_label_set_text(row->badge, label);
    gtk_image_set_from_icon_name(row->icon, icon);
    static const char *const classes[] = {"dim-label", "success", "warning"};
    for (gsize i = 0; i < G_N_ELEMENTS(classes); i++) {
        gtk_widget_remove_css_class(GTK_WIDGET(row->badge), classes[i]);
        gtk_widget_remove_css_class(GTK_WIDGET(row->icon), classes[i]);
    }
    gtk_widget_add_css_class(GTK_WIDGET(row->badge), css);
    gtk_widget_add_css_class(GTK_WIDGET(row->icon), css);
    const char *summary = string_member(data, "summary", "No recent verified observation. Check the status service or run an inspection.");
    g_autofree gchar *safe = octoshield_text_sanitize(summary, -1);
    JsonObject *profiles = object_member(root, "profiles");
    const char *assignment = g_str_equal(row->section, "controls") ? string_member(object_member(profiles, "assignments"), row->key, NULL) : NULL;
    const char *override = g_str_equal(row->section, "controls") ? string_member(object_member(profiles, "overrides"), row->key, NULL) : NULL;
    g_autofree gchar *subtitle = assignment != NULL ? g_strdup_printf("%s%s · %s", assignment, override != NULL ? " (override)" : "", safe) : g_strdup(safe);
    adw_action_row_set_subtitle(row->row, subtitle);
}

static void update_catalog(App *app, JsonArray *catalog)
{
    if (catalog == NULL || json_array_get_length(catalog) == 0 || json_array_get_length(catalog) > 128)
        return;
    g_autoptr(GPtrArray) ids = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GPtrArray) names = g_ptr_array_new_with_free_func(g_free);
    for (guint i = 0; i < json_array_get_length(catalog); i++) {
        JsonNode *node = json_array_get_element(catalog, i);
        if (!JSON_NODE_HOLDS_OBJECT(node)) return;
        JsonObject *item = json_node_get_object(node);
        const char *id = string_member(item, "id", "");
        if (!g_regex_match_simple("^[a-z][a-z0-9-]{0,31}$", id, 0, 0)) return;
        g_ptr_array_add(ids, g_strdup(id));
        g_ptr_array_add(names, octoshield_text_sanitize(string_member(item, "name", id), -1));
    }
    gboolean changed = ids->len != app->profile_ids->len;
    for (guint i = 0; !changed && i < ids->len; i++)
        changed = !g_str_equal(g_ptr_array_index(ids, i), g_ptr_array_index(app->profile_ids, i));
    if (!changed) return;
    for (guint i = 0; i < app->profile_selectors->len; i++) {
        GtkDropDown *selector = g_ptr_array_index(app->profile_selectors, i);
        const char *selected = selected_profile(app, selector);
        guint selected_index = 0;
        GtkStringList *model = gtk_string_list_new(NULL);
        for (guint j = 0; j < ids->len; j++) {
            gtk_string_list_append(model, g_ptr_array_index(names, j));
            if (g_strcmp0(selected, g_ptr_array_index(ids, j)) == 0) selected_index = j;
        }
        gtk_drop_down_set_model(selector, G_LIST_MODEL(model));
        gtk_drop_down_set_selected(selector, selected_index);
        g_object_unref(model);
    }
    g_ptr_array_unref(app->profile_ids);
    app->profile_ids = g_steal_pointer(&ids);
}

struct UsbDevice {
    App *app;
    gchar *id;
    gchar *token;
    gchar *profile;
    gchar *name;
    gchar *state;
    gchar *identity;
    gboolean remembered;
};

static void usb_device_free(gpointer data)
{
    UsbDevice *device = data;
    g_free(device->id); g_free(device->token); g_free(device->profile);
    g_free(device->name); g_free(device->state); g_free(device->identity);
    g_free(device);
}

static UsbDevice *usb_device_copy(const UsbDevice *device)
{
    UsbDevice *copy = g_new0(UsbDevice, 1);
    *copy = *device;
    copy->id = g_strdup(device->id); copy->token = g_strdup(device->token);
    copy->profile = g_strdup(device->profile); copy->name = g_strdup(device->name);
    copy->state = g_strdup(device->state); copy->identity = g_strdup(device->identity);
    return copy;
}

static gboolean usb_token_valid(const char *token)
{
    if (token == NULL || strlen(token) != 64) return FALSE;
    for (guint i = 0; i < 64; i++)
        if (!g_ascii_isxdigit(token[i]) || g_ascii_isupper(token[i])) return FALSE;
    return TRUE;
}

static gchar *usb_decision_key(const UsbDevice *device)
{
    return g_strdup_printf("%s:%s", device->profile, device->token);
}

static gboolean usb_device_current(App *app, const UsbDevice *device)
{
    if (!app->usb_cache_valid || !app->local_session_ready ||
        g_strcmp0(device->profile, app->usb_profile) != 0) return FALSE;
    for (guint i = 0; i < app->usb_inventory_rows->len; i++) {
        UsbDevice *current = g_ptr_array_index(app->usb_inventory_rows, i);
        if (g_str_equal(device->token, current->token) && g_str_equal(device->id, current->id) &&
            g_str_equal(device->state, current->state)) return TRUE;
    }
    return FALSE;
}

static gboolean usb_prompt_next(gpointer data)
{
    maybe_prompt_usb(data);
    return G_SOURCE_REMOVE;
}

static void usb_prompt_response(AdwMessageDialog *dialog, const char *response, gpointer data)
{
    UsbDevice *device = data;
    App *app = device->app;
    if (app->usb_prompt == dialog) app->usb_prompt = NULL;
    gboolean allow = g_str_equal(response, "once") || g_str_equal(response, "profile");
    if (allow && usb_device_current(app, device)) {
        const char *args[] = {"usb", "approve", device->id, device->token, device->profile, response};
        start_action(app, "Authorize USB device", NULL, TRUE, TRUE, G_N_ELEMENTS(args), args);
    } else if (allow) {
        toast(app, "The device, USB profile or session changed. Refresh and review it again.");
    }
    update_actions(app);
    if (!app->shutting_down) g_idle_add(usb_prompt_next, app);
}

static void show_usb_prompt(UsbDevice *device)
{
    App *app = device->app;
    if (app->shutting_down || app->usb_prompt != NULL || app->operation != NULL || app->preview != NULL ||
        app->smoke_test || !usb_device_current(app, device)) return;
    g_autofree gchar *key = usb_decision_key(device);
    g_hash_table_add(app->usb_decisions, g_strdup(key));
    gboolean already_allowed = g_str_equal(device->state, "allowed");
    GtkWidget *dialog = adw_message_dialog_new(app->window, already_allowed ? "Remember this USB device?" : "Allow this USB device?", NULL);
    g_autofree gchar *body = g_strdup_printf("%s\n%s\n\nUSB profile: %s\n\n%s Device names are supplied by the hardware and do not prove its identity.", device->name, device->identity, device->profile,
        already_allowed ? "This device is currently allowed. Remember it only if you trust it in this profile." : "Keep it blocked unless you expected this device.");
    adw_message_dialog_set_body(ADW_MESSAGE_DIALOG(dialog), body);
    const char *scope = device->remembered ?
        "This profile already remembers this device. Allow now resumes access; use Forget in the device list to remove its saved permission." : already_allowed ?
        "Remember saves permission in this USB profile, so it applies when the device reconnects here. Other profiles receive no permission." :
        "Allow once lasts until disconnect, a USB profile change or a USBGuard restart. Remember saves permission only in this USB profile.";
    GtkWidget *explanation = text_label(scope, "dim-label");
    adw_message_dialog_set_extra_child(ADW_MESSAGE_DIALOG(dialog), explanation);
    if (already_allowed)
        adw_message_dialog_add_responses(ADW_MESSAGE_DIALOG(dialog), "block", "Cancel", "profile", "Remember in profile", NULL);
    else {
        adw_message_dialog_add_responses(ADW_MESSAGE_DIALOG(dialog), "block", "Keep blocked", "once", device->remembered ? "Allow now" : "Allow once", "profile", "Remember in profile", NULL);
        adw_message_dialog_set_response_appearance(ADW_MESSAGE_DIALOG(dialog), "once", ADW_RESPONSE_SUGGESTED);
        adw_message_dialog_set_response_enabled(ADW_MESSAGE_DIALOG(dialog), "profile", !device->remembered);
    }
    adw_message_dialog_set_default_response(ADW_MESSAGE_DIALOG(dialog), "block");
    adw_message_dialog_set_close_response(ADW_MESSAGE_DIALOG(dialog), "block");
    app->usb_prompt = ADW_MESSAGE_DIALOG(dialog);
    UsbDevice *copy = usb_device_copy(device);
    g_object_set_data_full(G_OBJECT(dialog), "usb-device", copy, usb_device_free);
    g_signal_connect(dialog, "response", G_CALLBACK(usb_prompt_response), copy);
    update_actions(app);
    gtk_window_present(GTK_WINDOW(dialog));
}

static void maybe_prompt_usb(App *app)
{
    if ((!administrator_ready(app) && !app->usb_review_launch) || !app->usb_automatic || app->shutting_down || app->usb_inventory_rows == NULL || app->usb_prompt != NULL || !app->local_session_ready ||
        !app->usb_cache_valid || app->operation != NULL || app->preview != NULL || app->pending_request != NULL ||
        (app->session != NULL && !app->session->ready) || app->smoke_test) return;
    for (guint i = 0; i < app->usb_inventory_rows->len; i++) {
        UsbDevice *device = g_ptr_array_index(app->usb_inventory_rows, i);
        if ((!g_str_equal(device->state, "blocked") && !g_str_equal(device->state, "rejected")) || !usb_token_valid(device->token)) continue;
        g_autofree gchar *key = usb_decision_key(device);
        if (!g_hash_table_contains(app->usb_decisions, key)) { show_usb_prompt(device); return; }
    }
    if (app->usb_review_launch && !administrator_ready(app) && app->pending_request == NULL && app->session == NULL) gtk_window_close(app->window);
}

static void usb_review_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    show_usb_prompt(data);
}

static void usb_revoke_clicked(GtkButton *button, gpointer data)
{
    UsbDevice *device = data;
    App *app = device->app;
    if (!usb_device_current(app, device)) { toast(app, "Refresh the device list before changing this device"); return; }
    const char *mode = g_object_get_data(G_OBJECT(button), "usb-mode");
    g_autofree gchar *key = usb_decision_key(device);
    g_hash_table_add(app->usb_decisions, g_strdup(key));
    const char *args[] = {"usb", "revoke", device->id, device->token, device->profile, mode};
    start_action(app, g_str_equal(mode, "forget") ? "Forget USB approval" : "Block USB device", NULL, TRUE, TRUE, G_N_ELEMENTS(args), args);
}

static GtkWidget *usb_row_button(UsbDevice *device, const char *label, const char *mode)
{
    GtkWidget *button = gtk_button_new_with_label(label);
    gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
    if (mode != NULL) g_object_set_data(G_OBJECT(button), "usb-mode", (gpointer)mode);
    g_signal_connect(button, "clicked", mode != NULL ? G_CALLBACK(usb_revoke_clicked) : G_CALLBACK(usb_review_clicked), device);
    return button;
}

static void show_usb_devices(App *app, JsonArray *devices)
{
    if (app->usb_devices == NULL) return;
    g_autofree gchar *signature = NULL;
    if (devices != NULL && json_array_get_length(devices) <= 512) {
        g_autoptr(JsonNode) node = json_node_new(JSON_NODE_ARRAY);
        json_node_set_array(node, devices);
        g_autoptr(JsonGenerator) generator = json_generator_new();
        json_generator_set_root(generator, node);
        g_autofree gchar *json = json_generator_to_data(generator, NULL);
        g_autofree gchar *data = g_strconcat(app->usb_profile != NULL ? app->usb_profile : "", json, NULL);
        signature = g_compute_checksum_for_string(G_CHECKSUM_SHA256, data, -1);
    }
    if (signature != NULL && g_strcmp0(signature, app->usb_inventory_signature) == 0) {
        maybe_prompt_usb(app);
        return;
    }
    g_free(app->usb_inventory_signature);
    app->usb_inventory_signature = g_steal_pointer(&signature);
    /* Never leave actionable rows behind when the observation disappears. */
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(GTK_WIDGET(app->usb_devices))) != NULL)
        gtk_list_box_remove(app->usb_devices, child);
    g_ptr_array_set_size(app->usb_inventory_rows, 0);
    if (devices == NULL || json_array_get_length(devices) > 512) {
        GtkWidget *row = adw_action_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), "Device status unavailable");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(row), "Refresh after the status service has observed connected hardware.");
        gtk_list_box_append(app->usb_devices, row);
        if (app->usb_prompt != NULL) adw_message_dialog_response(app->usb_prompt, "block");
        return;
    }
    g_autoptr(GHashTable) attached = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    for (guint i = 0; i < json_array_get_length(devices); i++) {
        JsonNode *node = json_array_get_element(devices, i);
        if (node == NULL || !JSON_NODE_HOLDS_OBJECT(node)) continue;
        JsonObject *object = json_node_get_object(node);
        JsonNode *id_node = json_object_get_member(object, "id");
        if (id_node == NULL || !JSON_NODE_HOLDS_VALUE(id_node) || json_node_get_value_type(id_node) != G_TYPE_INT64) continue;
        gint64 id = json_node_get_int(id_node);
        if (id < 1 || id > G_GINT64_CONSTANT(4294967294)) continue;
        UsbDevice *device = g_new0(UsbDevice, 1);
        device->app = app;
        device->id = g_strdup_printf("%" G_GINT64_FORMAT, id);
        device->token = g_strdup(string_member(object, "token", ""));
        device->profile = g_strdup(string_member(object, "profile", app->usb_profile != NULL ? app->usb_profile : "unmanaged"));
        device->state = g_strdup(string_member(object, "state", "unknown"));
        const char *name = string_member(object, "name", "");
        if (*name == '\0') name = string_member(object, "label", "USB device");
        if (*name == '\0') name = "USB device";
        device->name = octoshield_text_sanitize(name, -1);
        g_autofree gchar *identity = g_strdup_printf("%s · %s · port %s", string_member(object, "category", "USB device"), string_member(object, "vendor_product", "identity unavailable"), string_member(object, "port", "unknown"));
        device->identity = octoshield_text_sanitize(identity, -1);
        JsonNode *remembered = json_object_get_member(object, "remembered");
        device->remembered = remembered != NULL && JSON_NODE_HOLDS_VALUE(remembered) && json_node_get_value_type(remembered) == G_TYPE_BOOLEAN && json_node_get_boolean(remembered);
        g_ptr_array_add(app->usb_inventory_rows, device);
        if (usb_token_valid(device->token)) g_hash_table_add(attached, usb_decision_key(device));
        GtkWidget *row = adw_action_row_new();
        adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), device->name);
        gboolean blocked = g_str_equal(device->state, "blocked") || g_str_equal(device->state, "rejected");
        gboolean allowed = g_str_equal(device->state, "allowed");
        const char *state = blocked ? "Blocked · decision required" : allowed ? (device->remembered ? "Allowed · remembered in this profile" : "Allowed · current policy") : "Authorization unknown";
        g_autofree gchar *subtitle = g_strdup_printf("%s\n%s", state, device->identity);
        adw_action_row_set_subtitle(ADW_ACTION_ROW(row), subtitle);
        adw_action_row_set_subtitle_lines(ADW_ACTION_ROW(row), 3);
        GtkWidget *icon = gtk_image_new_from_icon_name(blocked ? "changes-prevent-symbolic" : allowed ? "emblem-ok-symbolic" : "dialog-question-symbolic");
        gtk_widget_add_css_class(icon, blocked ? "warning" : allowed ? "success" : "dim-label");
        adw_action_row_add_prefix(ADW_ACTION_ROW(row), icon);
        if (usb_token_valid(device->token)) {
            GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
            if (blocked) gtk_box_append(GTK_BOX(buttons), usb_row_button(device, "Review…", NULL));
            if (allowed) gtk_box_append(GTK_BOX(buttons), usb_row_button(device, "Block…", "block"));
            if (allowed && !device->remembered) gtk_box_append(GTK_BOX(buttons), usb_row_button(device, "Remember…", NULL));
            if (device->remembered) gtk_box_append(GTK_BOX(buttons), usb_row_button(device, "Forget…", "forget"));
            adw_action_row_add_suffix(ADW_ACTION_ROW(row), buttons);
        }
        gtk_list_box_append(app->usb_devices, row);
    }
    GHashTableIter iter; gpointer key;
    g_hash_table_iter_init(&iter, app->usb_decisions);
    while (g_hash_table_iter_next(&iter, &key, NULL))
        if (!g_hash_table_contains(attached, key)) g_hash_table_iter_remove(&iter);
    if (app->usb_inventory_rows->len == 0) {
        GtkWidget *row = adw_action_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), "No external USB devices detected");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(row), "Connected devices and their authorization will appear here automatically.");
        gtk_list_box_append(app->usb_devices, row);
    }
    if (app->usb_prompt != NULL) {
        UsbDevice *prompted = g_object_get_data(G_OBJECT(app->usb_prompt), "usb-device");
        if (!usb_device_current(app, prompted)) adw_message_dialog_response(app->usb_prompt, "block");
    }
    update_actions(app);
    maybe_prompt_usb(app);
}

static void render_usb_status(App *app, JsonObject *usb)
{
    JsonNode *available = usb != NULL ? json_object_get_member(usb, "available") : NULL;
    app->usb_cache_valid = available != NULL && JSON_NODE_HOLDS_VALUE(available) && json_node_get_value_type(available) == G_TYPE_BOOLEAN && json_node_get_boolean(available);

    JsonNode *pending_node = usb != NULL ? json_object_get_member(usb, "pending") : NULL;
    gint64 pending = app->usb_cache_valid && pending_node != NULL && JSON_NODE_HOLDS_VALUE(pending_node) && json_node_get_value_type(pending_node) == G_TYPE_INT64 ? json_node_get_int(pending_node) : -1;
    const char *usb_profile = string_member(usb, "profile", "not assigned");
    g_autofree gchar *pending_text = pending < 0 ? g_strdup(string_member(usb, "summary", "USB status unavailable. New devices are not assumed to be blocked until authorization is verified.")) :
        g_strdup_printf("USB profile: %s · %" G_GINT64_FORMAT " blocked device%s awaiting a decision. Approval is scoped to this USB profile.", usb_profile, pending, pending == 1 ? "" : "s");
    gtk_label_set_text(app->usb_pending, pending_text);
    if (app->overview_usb != NULL) gtk_label_set_text(app->overview_usb, pending_text);
    g_free(app->usb_profile);
    app->usb_profile = g_strdup(usb_profile);
    show_usb_devices(app, app->usb_cache_valid ? array_member(usb, "devices") : NULL);
}

static void render_status(App *app, JsonObject *root)
{
    if (app->status_rows == NULL) return;
    app->cache_valid = root != NULL;
    for (guint i = 0; i < app->status_rows->len; i++)
        update_status_row(g_ptr_array_index(app->status_rows, i), root);
    JsonObject *profiles = object_member(root, "profiles");
    update_catalog(app, array_member(profiles, "catalog"));
    const char *firewall = string_member(object_member(profiles, "assignments"), "firewall", NULL);
    if (firewall != NULL && g_strcmp0(app->firewall_profile, firewall) != 0) {
        g_free(app->firewall_profile);
        app->firewall_profile = g_strdup(firewall);
        if (app->access_profile != NULL) {
            access_cancel_edit(NULL, app);
            clear_list(app->access_rules);
            const char *selected = g_str_equal(firewall, "unmanaged") ? "home" : firewall;
            for (guint i = 0; i < app->profile_ids->len; i++)
                if (g_str_equal(g_ptr_array_index(app->profile_ids, i), selected)) gtk_drop_down_set_selected(app->access_profile, i);
        }
        app->access_loaded = FALSE;
    }
    const char *active = string_member(profiles, "active", "Not selected");
    g_free(app->active_profile);
    app->active_profile = g_strdup(active);
    JsonObject *overrides = object_member(profiles, "overrides");
    gboolean mixed = overrides != NULL && json_object_get_size(overrides) > 0;
    gboolean incomplete = FALSE;
    JsonObject *results = object_member(profiles, "results");
    if (results != NULL) {
        g_autoptr(GList) keys = json_object_get_members(results);
        for (GList *key = keys; key != NULL; key = key->next) {
            const char *result = string_member(object_member(results, key->data), "status", "unknown");
            incomplete |= g_str_equal(result, "failed") || g_str_equal(result, "pending") || g_str_equal(result, "applying");
        }
    }
    g_autofree gchar *title = root == NULL ? g_strdup("Current status unavailable") : g_strdup_printf("%s%s%s", active, mixed ? " · individual overrides" : "", incomplete ? " · changes incomplete" : "");
    gtk_label_set_text(app->overview_title, title);
    gtk_label_set_text(app->overview_summary, root == NULL ? "No recent system observation. Protection remains unknown until verified." :
                       mixed ? "Individual controls use different profiles. Check their effective assignments below." :
                       "Current system observations are shown below. Applying a profile globally clears individual overrides.");
    if (root != NULL) {
        gint64 checked = json_object_get_int_member(root, "checked_at");
        g_autoptr(GDateTime) when = g_date_time_new_from_unix_local(checked);
        g_autofree gchar *time = when != NULL ? g_date_time_format(when, "%H:%M:%S") : g_strdup("unknown");
        g_autofree gchar *label = g_strdup_printf("Last system observation %s · refreshes automatically", time);
        gtk_label_set_text(app->checked_label, label);
    } else gtk_label_set_text(app->checked_label, "Status is missing, stale or invalid. Inspection can help diagnose the service.");
    if (!app->auth_required) render_usb_status(app, object_member(root, "usb"));
}

/* The directory cannot be replaced by another user; the opened file is then
 * checked itself before its bounded contents are parsed. Never follow links,
 * trust user-writable status, or preserve green indicators after expiry. */
static JsonNode *read_observation_cache(const char *filename, gint64 max_age)
{
    int directory = open("/run/octoshield", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return NULL;
    struct stat info;
    if (fstat(directory, &info) != 0 || info.st_uid != 0 || info.st_gid != 0 || (info.st_mode & 07777) != 0755) {
        close(directory); return NULL;
    }
    int fd = openat(directory, filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    close(directory);
    if (fd < 0) return NULL;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 || info.st_gid != 0 ||
        (info.st_mode & 07777) != 0644 || info.st_size < 2 || info.st_size > 262144) {
        close(fd); return NULL;
    }
    g_autofree gchar *data = g_malloc((gsize)info.st_size + 1);
    gsize used = 0;
    while (used < (gsize)info.st_size) {
        ssize_t count = read(fd, data + used, (gsize)info.st_size - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return NULL; }
        used += (gsize)count;
    }
    close(fd); data[used] = '\0';
    g_autoptr(JsonParser) parser = json_parser_new();
    if (!g_utf8_validate(data, (gssize)used, NULL) || memchr(data, '\0', used) != NULL ||
        !json_parser_load_from_data(parser, data, (gssize)used, NULL)) return NULL;
    JsonNode *root = json_parser_get_root(parser);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) return NULL;
    JsonObject *object = json_node_get_object(root);
    JsonNode *schema = json_object_get_member(object, "schema");
    JsonNode *checked = json_object_get_member(object, "checked_at");
    if (schema == NULL || checked == NULL || !JSON_NODE_HOLDS_VALUE(schema) || !JSON_NODE_HOLDS_VALUE(checked) ||
        json_node_get_value_type(schema) != G_TYPE_INT64 || json_node_get_value_type(checked) != G_TYPE_INT64 ||
        json_node_get_int(schema) != 1) return NULL;
    gint64 now = g_get_real_time() / G_USEC_PER_SEC;
    gint64 observed = json_node_get_int(checked);
    return observed >= 0 && observed <= now && now - observed <= max_age ? json_node_copy(root) : NULL;
}

static gboolean refresh_status(gpointer data)
{
    App *app = data;
    if (app->shutting_down || app->status_rows == NULL) return G_SOURCE_CONTINUE;
    g_autoptr(JsonNode) root = read_observation_cache("status.json", 90);
    if (root != NULL && json_object_get_int_member(json_node_get_object(root), "checked_at") < app->status_not_before)
        g_clear_pointer(&root, json_node_unref);
    render_status(app, root != NULL ? json_node_get_object(root) : NULL);
    if (app->auth_required) {
        g_autoptr(JsonNode) usb_snapshot = read_observation_cache("usb.json", 10);
        if (usb_snapshot != NULL && json_object_get_int_member(json_node_get_object(usb_snapshot), "checked_at") < app->usb_status_not_before)
            g_clear_pointer(&usb_snapshot, json_node_unref);
        JsonObject *usb = usb_snapshot != NULL ? object_member(json_node_get_object(usb_snapshot), "usb") : NULL;
        render_usb_status(app, usb);
        g_autoptr(JsonObject) observed = json_object_new();
        JsonObject *controls = json_object_new();
        json_object_set_object_member(observed, "controls", controls);
        if (usb != NULL) json_object_set_object_member(controls, "usb", json_object_ref(usb));
        JsonObject *profiles = json_object_new();
        JsonObject *assignments = json_object_new();
        json_object_set_object_member(observed, "profiles", profiles);
        json_object_set_object_member(profiles, "assignments", assignments);
        json_object_set_string_member(assignments, "usb", app->usb_profile != NULL ? app->usb_profile : "unknown");
        for (guint i = 0; i < app->status_rows->len; i++) {
            StatusRow *row = g_ptr_array_index(app->status_rows, i);
            if (g_str_equal(row->section, "controls") && g_str_equal(row->key, "usb")) update_status_row(row, observed);
        }
    }
    return G_SOURCE_CONTINUE;
}

static void refresh_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    refresh_status(data);
}

static void handle_data_log(App *app, const char *text)
{
    if (app->operation == NULL || app->update_status == NULL) return;
    g_autoptr(JsonParser) parser = json_parser_new();
    if (!json_parser_load_from_data(parser, text, -1, NULL)) return;
    JsonNode *node = json_parser_get_root(parser);
    if (node == NULL) return;
    if (g_str_equal(app->operation->title, "Refresh device list")) {
        if (JSON_NODE_HOLDS_ARRAY(node)) show_usb_devices(app, json_node_get_array(node));
        else if (JSON_NODE_HOLDS_OBJECT(node)) show_usb_devices(app, array_member(json_node_get_object(node), "devices"));
        app->usb_inventory = TRUE;
        app->operation->data_seen = TRUE;
        return;
    }
    if (!JSON_NODE_HOLDS_OBJECT(node)) return;
    JsonObject *root = json_node_get_object(node);
    const char *kind = string_member(root, "kind", "");
    if (g_str_equal(app->operation->title, "Refresh access permissions") && g_str_equal(kind, "access")) {
        app->operation->data_seen = show_access(app, root); return;
    }
    if (g_str_equal(app->operation->title, "Refresh connections") && g_str_equal(kind, "connections")) {
        app->operation->data_seen = show_connections(app, root); return;
    }
    if (g_str_equal(app->operation->title, "Review protection details") && g_str_equal(kind, "diagnostics")) {
        app->operation->data_seen = show_diagnostics(app, root); return;
    }
    if (g_str_equal(app->operation->title, "Review container local access") && g_str_equal(kind, "container-plan")) {
        app->operation->data_seen = show_container_plan(app, root); return;
    }
    if (g_str_equal(app->operation->title, "Check for OctoShield updates")) {
        const char *current = string_member(root, "current", "unknown");
        const char *latest = string_member(root, "latest", "unknown");
        const char *message = string_member(root, "message", "Unable to determine the latest package.");
        g_autofree gchar *label = g_strdup_printf("Installed %s · latest %s\n%s", current, latest, message);
        gtk_label_set_text(app->update_status, label);
        const char *url = string_member(root, "download_url", "");
        if (!g_str_has_prefix(url, "https://github.com/octoleo/octoshield/releases/download/v"))
            url = "https://github.com/octoleo/octoshield/releases/latest";
        gtk_link_button_set_uri(app->update_link, url);
        app->operation->data_seen = TRUE;
    } else if (g_str_equal(app->operation->title, "Inspect profile configuration")) {
        const char *id = string_member(root, "id", "unknown");
        GString *configuration = g_string_new(NULL);
        g_string_append_printf(configuration, "Saved profile: %s\n", string_member(root, "name", id));
        GHashTableIter iter;
        gpointer key;
        gpointer value;
        g_hash_table_iter_init(&iter, app->setting_choices);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            g_auto(GStrv) path = g_strsplit(key, ".", 2);
            JsonObject *section = object_member(root, path[0]);
            JsonNode *setting = section != NULL ? json_object_get_member(section, path[1]) : NULL;
            gboolean service = g_str_has_prefix(key, "services.");
            guint selection = service ? 3U : 2U;
            const char *description = "unknown";
            if (setting != NULL && JSON_NODE_HOLDS_VALUE(setting)) {
                if (!service && json_node_get_value_type(setting) == G_TYPE_BOOLEAN) {
                    selection = json_node_get_boolean(setting) ? 0 : 1;
                    description = selection == 0 ? "enabled" : "disabled";
                } else if (service && json_node_get_value_type(setting) == G_TYPE_STRING) {
                    description = json_node_get_string(setting);
                    selection = g_str_equal(description, "enabled") ? 0 : g_str_equal(description, "disabled") ? 1 : g_str_equal(description, "baseline") ? 2 : 3;
                }
            }
            if (g_strcmp0(id, selected_profile(app, app->edit_profile)) == 0)
                gtk_drop_down_set_selected(value, selection);
            const char *setting_title = g_object_get_data(G_OBJECT(value), "setting-title");
            g_string_append_printf(configuration, "%s: %s\n", setting_title != NULL ? setting_title : (char *)key, description);
        }
        JsonArray *rules = array_member(object_member(root, "firewall"), "rules");
        g_string_append_printf(configuration, "\nSaved firewall exceptions: %u\n", rules != NULL ? json_array_get_length(rules) : 0);
        if (rules != NULL) for (guint i = 0; i < json_array_get_length(rules); i++) {
            JsonNode *rule_node = json_array_get_element(rules, i);
            if (!JSON_NODE_HOLDS_OBJECT(rule_node)) continue;
            JsonObject *rule = json_node_get_object(rule_node);
            JsonNode *port = json_object_get_member(rule, "port");
            gint64 number = port != NULL && JSON_NODE_HOLDS_VALUE(port) && json_node_get_value_type(port) == G_TYPE_INT64 ? json_node_get_int(port) : 0;
            JsonNode *expires_node = json_object_get_member(rule, "expires_at");
            gint64 expires = expires_node != NULL && JSON_NODE_HOLDS_VALUE(expires_node) && json_node_get_value_type(expires_node) == G_TYPE_INT64 ? json_node_get_int(expires_node) : -1;
            g_autoptr(GDateTime) when = expires > 0 ? g_date_time_new_from_unix_local(expires) : NULL;
            g_autofree gchar *expiry = when != NULL ? g_date_time_format(when, "%Y-%m-%d %H:%M") : g_strdup(expires == 0 ? "no expiry" : "expiry unknown");
            g_string_append_printf(configuration, "%s: %s port %" G_GINT64_FORMAT " from %s on %s · %s%s\n", string_member(rule, "id", "unknown"), string_member(rule, "protocol", "unknown"), number, string_member(rule, "source", "unknown"), string_member(rule, "interface", "unknown"), expiry, expires > 0 ? " or earlier on firewall reload/reboot" : "");
        }
        gtk_label_set_text(app->profile_details, configuration->str);
        g_string_free(configuration, TRUE);
        app->operation->data_seen = TRUE;
    }
}

static void open_usb_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    gtk_list_box_select_row(app->navigation, gtk_list_box_get_row_at_index(app->navigation, 2));
}

static void build_overview(App *app)
{
    GtkWidget *page = page_new(app, "overview", "Overview", "Choose an environment and see what is actually active.");
    GtkWidget *hero = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 18);
    gtk_widget_add_css_class(hero, "shield-hero");
    gtk_box_append(GTK_BOX(hero), brand_widget(app, 52, 60));
    GtkWidget *copy = gtk_box_new(GTK_ORIENTATION_VERTICAL, 7);
    gtk_widget_set_hexpand(copy, TRUE);
    app->overview_title = GTK_LABEL(text_label("Reading current status…", "title-2"));
    app->overview_summary = GTK_LABEL(text_label("Waiting for a current system observation.", NULL));
    gtk_box_append(GTK_BOX(copy), GTK_WIDGET(app->overview_title));
    gtk_box_append(GTK_BOX(copy), GTK_WIDGET(app->overview_summary));
    gtk_box_append(GTK_BOX(hero), copy);
    app->global_profile = GTK_DROP_DOWN(profile_selector(app));
    GtkWidget *controls = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_valign(controls, GTK_ALIGN_CENTER);
    gtk_widget_set_tooltip_text(controls, "Apply this environment to firewall, USB, connections, services and monitoring. This clears individual overrides.");
    gtk_box_append(GTK_BOX(controls), GTK_WIDGET(app->global_profile));
    GtkWidget *apply = profile_button(app, "Apply profile", PROFILE_APPLY, app->global_profile, NULL, NULL, NULL, NULL);
    gtk_widget_add_css_class(apply, "suggested-action");
    gtk_box_append(GTK_BOX(controls), apply);
    gtk_box_append(GTK_BOX(hero), controls);
    gtk_box_append(GTK_BOX(page), hero);
    GtkWidget *group = group_new(page, "Observed protection", "Indicators report verified conditions, including incomplete or unsupported protection.");
    group_add(group, status_row(app, "controls", "firewall", "Network firewall"));
    group_add(group, status_row(app, "controls", "usb", "USB authorization"));
    group_add(group, status_row(app, "controls", "network", "Connection privacy"));
    group_add(group, status_row(app, "controls", "services", "Listening services"));
    app->overview_usb = GTK_LABEL(text_label("Checking USB decisions…", NULL));
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->overview_usb));
    GtkWidget *decisions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *review_usb = gtk_button_new_with_label("Review USB devices");
    g_signal_connect(review_usb, "clicked", G_CALLBACK(open_usb_clicked), app);
    gtk_box_append(GTK_BOX(decisions), review_usb);
    gtk_box_append(GTK_BOX(decisions), action_button(app, "notify-enable", "Enable desktop alerts…", FALSE));
    gtk_box_append(GTK_BOX(page), decisions);
    app->checked_label = GTK_LABEL(text_label("Checking observation freshness…", "dim-label"));
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->checked_label));
    GtkWidget *refresh = gtk_button_new_with_label("Refresh status");
    gtk_widget_set_halign(refresh, GTK_ALIGN_END);
    g_signal_connect(refresh, "clicked", G_CALLBACK(refresh_clicked), app);
    gtk_box_append(GTK_BOX(page), refresh);
    group = group_new(page, "Additional exposure and baseline", "These observations have limits. An unavailable check is shown explicitly, and profiles never turn off your essential baseline protection.");
    static const char *const exposure[][2] = {{"secure_boot", "Secure Boot"}, {"disk_encryption", "System storage encryption"}, {"thunderbolt", "Thunderbolt / USB4 and DMA protection"}, {"containers", "Docker published ports"}, {"forwarding", "Network forwarding"}};
    for (gsize i = 0; i < G_N_ELEMENTS(exposure); i++)
        group_add(group, status_row(app, "exposures", exposure[i][0], exposure[i][1]));
}

static void edit_profile_changed(GObject *object, GParamSpec *property, gpointer data)
{
    (void)object; (void)property;
    App *app = data;
    reset_profile_choices(app);
    gtk_label_set_text(app->profile_details, "Inspect this profile to view its saved settings, or choose a new value before saving.");
}

static void build_protections(App *app)
{
    GtkWidget *page = page_new(app, "protections", "Profiles & protections", "Use an environment for each control, or restore its previous settings. Authentication is requested only when you perform a system operation.");
    GtkWidget *group = group_new(page, "Individual profile assignments", "Apply the global profile to one control to remove its override. The status reports the current assignment and observed result.");
    static const char *const controls[][2] = {{"firewall", "Network firewall"}, {"usb", "USB authorization"}, {"network", "Connection privacy"}, {"services", "Listening services"}, {"monitor", "Security monitoring"}};
    for (gsize i = 0; i < G_N_ELEMENTS(controls); i++) {
        group_add(group, status_row(app, "controls", controls[i][0], controls[i][1]));
        GtkDropDown *selector = GTK_DROP_DOWN(profile_selector(app));
        GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_append(GTK_BOX(buttons), GTK_WIDGET(selector));
        gtk_box_append(GTK_BOX(buttons), profile_button(app, "Apply", PROFILE_APPLY, selector, controls[i][0], NULL, NULL, NULL));
        gtk_box_append(GTK_BOX(buttons), profile_button(app, "Restore…", PROFILE_RESTORE, NULL, controls[i][0], NULL, NULL, NULL));
        group_add(group, control_row("Adjust this protection", NULL, buttons));
    }
    group = group_new(page, "Baseline protection", "These independent controls stay in place when switching environments.");
    static const char *const baseline[][3] = {{"sudo", "Fresh administrator authentication", "dialog-password-symbolic"}, {"updates", "Security updates", "software-update-available-symbolic"}, {"apparmor", "Application confinement", "security-high-symbolic"}};
    for (gsize i = 0; i < G_N_ELEMENTS(baseline); i++) {
        group_add(group, status_row(app, "controls", baseline[i][0], baseline[i][1]));
        group_add(group, action_row(app, baseline[i][0], "Activate", baseline[i][2]));
    }
    group = group_new(page, "Create and customize profiles", "Changes are saved first. Apply the edited profile globally or to an individual control when ready. Profile names use lowercase letters, numbers and hyphens.");
    app->edit_profile = GTK_DROP_DOWN(profile_selector(app));
    group_add(group, control_row("Profile to edit or copy", NULL, GTK_WIDGET(app->edit_profile)));
    GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(buttons), profile_button(app, "Inspect configuration", PROFILE_SHOW, app->edit_profile, NULL, NULL, NULL, NULL));
    gtk_box_append(GTK_BOX(buttons), profile_button(app, "Delete…", PROFILE_DELETE, app->edit_profile, NULL, NULL, NULL, NULL));
    group_add(group, control_row("Saved settings", "Active profiles cannot be deleted.", buttons));
    GtkWidget *name = input_row(group, "New profile name · for example client-visit");
    GtkWidget *name_fields[] = {name, NULL};
    group_add(group, control_row("Copy selected profile", "Includes its settings and remembered USB permissions.", profile_button(app, "Create profile", PROFILE_CREATE, app->edit_profile, NULL, NULL, NULL, name_fields)));
    static const char *const settings[][2] = {{"network.autoconnect", "Previously trusted automatic connections"}, {"network.discovery", "Local network discovery"}, {"services.printing", "Printing service"}, {"services.bluetooth", "Bluetooth service"}, {"services.ssh", "Incoming SSH service"}, {"services.discovery", "Discovery service"}, {"services.samba", "File sharing service"}, {"services.remote_desktop", "System remote desktop service"}, {"monitor.enabled", "Security event monitoring"}};
    static const char *const boolean_choices[] = {"Enabled", "Disabled", "Choose a value…", NULL};
    static const char *const service_choices[] = {"Enabled", "Disabled", "Previous setting", "Choose a value…", NULL};
    for (gsize i = 0; i < G_N_ELEMENTS(settings); i++) {
        GtkDropDown *choice = GTK_DROP_DOWN(gtk_drop_down_new_from_strings(g_str_has_prefix(settings[i][0], "services.") ? service_choices : boolean_choices));
        gtk_drop_down_set_selected(choice, g_str_has_prefix(settings[i][0], "services.") ? 3 : 2);
        g_hash_table_insert(app->setting_choices, (gpointer)settings[i][0], choice);
        g_object_set_data(G_OBJECT(choice), "setting-title", (gpointer)settings[i][1]);
        GtkWidget *edit = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_append(GTK_BOX(edit), GTK_WIDGET(choice));
        gtk_box_append(GTK_BOX(edit), profile_button(app, "Save", PROFILE_SET, app->edit_profile, NULL, settings[i][0], choice, NULL));
        group_add(group, control_row(settings[i][1], "Choose a value, then save it to the selected profile.", edit));
    }
    app->profile_details = GTK_LABEL(text_label("Inspect a profile to view its saved configuration and firewall rule identifiers.", "dim-label"));
    gtk_label_set_selectable(app->profile_details, TRUE);
    g_signal_connect(app->edit_profile, "notify::selected", G_CALLBACK(edit_profile_changed), app);
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->profile_details));
    group = group_new(page, "Your GNOME session", "Desktop settings are changed as your normal user and have their own private baseline.");
    group_add(group, action_row(app, "desktop-apply", "Activate", "system-lock-screen-symbolic"));
    group_add(group, action_row(app, "desktop-status", "Inspect", "dialog-information-symbolic"));
    group_add(group, action_row(app, "desktop-restore", "Restore…", "edit-undo-symbolic"));
    GtkWidget *accounts = gtk_button_new_with_label("Open Accounts");
    g_signal_connect(accounts, "clicked", G_CALLBACK(accounts_clicked), app);
    g_ptr_array_add(app->operation_widgets, accounts);
    group_add(group, control_row("Change your password", "Use GNOME Accounts. OctoShield never receives or stores your password.", accounts));
}

static gchar *usb_preferences_path(void)
{
    return g_build_filename(g_get_user_config_dir(), "octoshield", "preferences.ini", NULL);
}

static gboolean usb_automatic_preference(void)
{
    g_autofree gchar *path = usb_preferences_path();
    g_autoptr(GKeyFile) settings = g_key_file_new();
    g_autoptr(GError) error = NULL;
    if (!g_key_file_load_from_file(settings, path, G_KEY_FILE_NONE, NULL)) return TRUE;
    gboolean enabled = g_key_file_get_boolean(settings, "USB", "automatic-prompts", &error);
    return error != NULL ? TRUE : enabled;
}

static void usb_automatic_changed(GObject *object, GParamSpec *property, gpointer data)
{
    (void)property;
    App *app = data;
    gboolean enabled = gtk_switch_get_active(GTK_SWITCH(object));
    if (enabled == app->usb_automatic) return;
    g_autofree gchar *path = usb_preferences_path();
    g_autofree gchar *directory = g_path_get_dirname(path);
    g_autoptr(GError) error = NULL;
    struct stat info;
    gboolean safe = g_mkdir_with_parents(directory, 0700) == 0 && lstat(directory, &info) == 0 &&
        S_ISDIR(info.st_mode) && info.st_uid == getuid() && chmod(directory, 0700) == 0;
    if (safe && lstat(path, &info) == 0) safe = S_ISREG(info.st_mode) && info.st_uid == getuid() && info.st_nlink == 1;
    g_autoptr(GKeyFile) settings = g_key_file_new();
    if (safe) {
        g_key_file_load_from_file(settings, path, G_KEY_FILE_KEEP_COMMENTS, NULL);
        g_key_file_set_boolean(settings, "USB", "automatic-prompts", enabled);
        gsize size = 0;
        g_autofree gchar *contents = g_key_file_to_data(settings, &size, NULL);
        safe = g_file_set_contents_full(path, contents, (gssize)size,
            G_FILE_SET_CONTENTS_CONSISTENT | G_FILE_SET_CONTENTS_DURABLE, 0600, &error);
    }
    if (!safe) {
        gtk_switch_set_active(GTK_SWITCH(object), app->usb_automatic);
        show_error(app, "Unable to save USB prompt preference", error != NULL ? error->message : "The preference location must be a private directory owned by your user.");
        return;
    }
    app->usb_automatic = enabled;
    if (enabled) maybe_prompt_usb(app);
}

static void build_usb(App *app)
{
    GtkWidget *page = page_new(app, "usb", "USB devices", "Unknown devices remain blocked while authorization is active. Remembered approvals belong only to the effective USB profile; device names alone cannot prove identity.");
    app->usb_pending = GTK_LABEL(text_label("Checking pending USB devices…", "title-3"));
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->usb_pending));
    GtkWidget *alerts = group_new(page, "Device decisions", "New blocked devices open a decision dialog in your unlocked local desktop. Cancel always leaves a device blocked; an administrator must authenticate before the first approval.");
    GtkWidget *automatic = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(automatic), app->usb_automatic);
    g_signal_connect(automatic, "notify::active", G_CALLBACK(usb_automatic_changed), app);
    group_add(alerts, control_row("Ask when a new device is connected", "Controls automatic dialogs for your user. You can always review devices here.", automatic));
    g_ptr_array_add(app->operation_widgets, automatic);
    group_add(alerts, action_row(app, "notify-enable", "Enable alerts…", "preferences-system-notifications-symbolic"));
    GtkWidget *group = group_new(page, "Connected hardware", "Device state refreshes automatically. Review a blocked device to allow it once or remember it in this USB profile. Refresh never asks for another password during this administrator session.");
    group_add(group, status_row(app, "controls", "usb", "USB authorization"));
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    g_signal_connect(refresh, "clicked", G_CALLBACK(refresh_clicked), app);
    g_ptr_array_add(app->operation_widgets, refresh);
    group_add(group, control_row("Refresh device state", "Reads the latest observation without another administrator request.", refresh));
    app->usb_devices = GTK_LIST_BOX(gtk_list_box_new());
    gtk_list_box_set_selection_mode(app->usb_devices, GTK_SELECTION_NONE);
    gtk_widget_add_css_class(GTK_WIDGET(app->usb_devices), "boxed-list");
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->usb_devices));
    group = group_new(page, "Prepare another USB profile", "Enroll only physically reviewed devices. Keep essential input devices available and safely unmount storage before restrictive changes.");
    GtkDropDown *profile = GTK_DROP_DOWN(profile_selector(app));
    group_add(group, control_row("Destination profile", NULL, GTK_WIDGET(profile)));
    group_add(group, control_row("Review the connected device set", NULL, profile_button(app, "Enroll devices…", PROFILE_ENROLL, profile, NULL, NULL, NULL, NULL)));
    gtk_box_append(GTK_BOX(page), text_label("USB authorization is separate from file scanning and encryption. Blocking your active input or network device can disconnect it immediately; unmount storage before blocking it.", "dim-label"));
}

typedef struct {
    gchar *label;
    gchar *source;
    gchar *interface;
} LanOption;

typedef struct {
    App *app;
    JsonObject *rule;
} AccessRule;

static void lan_option_free(gpointer data)
{
    LanOption *option = data;
    g_free(option->label); g_free(option->source); g_free(option->interface); g_free(option);
}

static void access_rule_free(gpointer data)
{
    AccessRule *rule = data;
    json_object_unref(rule->rule); g_free(rule);
}

static gboolean boolean_member(JsonObject *object, const char *name)
{
    JsonNode *node = object != NULL ? json_object_get_member(object, name) : NULL;
    return node != NULL && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == G_TYPE_BOOLEAN && json_node_get_boolean(node);
}

static void clear_list(GtkListBox *list)
{
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(GTK_WIDGET(list))) != NULL) gtk_list_box_remove(list, child);
}

static void select_page(App *app, const char *name)
{
    if (app->navigation != NULL) {
        for (GtkWidget *row = gtk_widget_get_first_child(GTK_WIDGET(app->navigation)); row != NULL; row = gtk_widget_get_next_sibling(row)) {
            if (g_strcmp0(g_object_get_data(G_OBJECT(row), "page-name"), name) == 0) {
                gtk_list_box_select_row(app->navigation, GTK_LIST_BOX_ROW(row));
                return;
            }
        }
    }
    gtk_stack_set_visible_child_name(app->pages, name);
}

static gboolean refresh_private(gpointer data)
{
    App *app = data;
    app->private_refresh_idle = 0;
    if (app->shutting_down || app->smoke_test || !administrator_ready(app)) {
        app->private_refresh = 0;
        return G_SOURCE_REMOVE;
    }
    if (app->operation != NULL || app->preview != NULL || app->usb_prompt != NULL) return G_SOURCE_REMOVE;
    if (app->private_refresh & 1U) {
        app->private_refresh &= ~1U;
        const char *profile = app->firewall_profile != NULL && !g_str_equal(app->firewall_profile, "unmanaged") ? selected_profile(app, app->access_profile) : NULL;
        const char *args[] = {"access", "list", profile};
        start_action(app, "Refresh access permissions", NULL, TRUE, FALSE, profile != NULL ? 3 : 2, args);
    } else if (app->private_refresh & 2U) {
        app->private_refresh &= ~2U;
        const char *args[] = {"connections", "list"};
        start_action(app, "Refresh connections", NULL, TRUE, FALSE, G_N_ELEMENTS(args), args);
    } else if (app->private_refresh & 4U) {
        app->private_refresh &= ~4U;
        const char *args[] = {"diagnostics", "show", "containers"};
        start_action(app, "Review protection details", NULL, TRUE, FALSE, G_N_ELEMENTS(args), args);
    }
    return G_SOURCE_REMOVE;
}

static void queue_private_refresh(App *app, guint flags)
{
    app->private_refresh |= flags;
    if (app->private_refresh_idle == 0) app->private_refresh_idle = g_idle_add(refresh_private, app);
}

static void access_refresh_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    queue_private_refresh(data, 3U);
}

static void connections_refresh_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    queue_private_refresh(data, 2U);
}

static void review_status_clicked(GtkButton *button, gpointer data)
{
    App *app = data;
    const char *topic = g_object_get_data(G_OBJECT(button), "topic");
    if (g_strcmp0(topic, "firewall") == 0) { select_page(app, "office"); queue_private_refresh(app, 3U); return; }
    if (g_strcmp0(topic, "network") == 0 && !g_object_get_data(G_OBJECT(button), "inspect-network")) { select_page(app, "privacy"); queue_private_refresh(app, 2U); return; }
    const char *args[] = {"diagnostics", "show", topic};
    select_page(app, "diagnostics");
    gtk_label_set_text(app->diagnostics_summary, "Inspecting current evidence and configuration sources…");
    clear_list(app->diagnostics_findings);
    start_action(app, "Review protection details", NULL, TRUE, FALSE, G_N_ELEMENTS(args), args);
}

static GtkWidget *managed_button(App *app, const char *label, GCallback callback)
{
    GtkWidget *button = gtk_button_new_with_label(label);
    gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
    g_signal_connect(button, "clicked", callback, app);
    g_ptr_array_add(app->operation_widgets, button);
    return button;
}

static void access_choices_changed(GObject *object, GParamSpec *property, gpointer data)
{
    (void)object; (void)property;
    App *app = data;
    gtk_widget_set_visible(app->access_custom, gtk_drop_down_get_selected(app->access_preset) == 2);
    guint scope = gtk_drop_down_get_selected(app->access_scope);
    gtk_widget_set_visible(app->access_network_row, scope == 0);
    gtk_widget_set_visible(app->access_address, scope == 1);
}

static void access_cancel_edit(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    g_clear_pointer(&app->access_edit_id, g_free);
    g_clear_pointer(&app->access_edit_profile, g_free);
    gtk_label_set_text(app->access_editing, "Choose what to share and who may connect. Localhost access needs no incoming firewall permission.");
    gtk_button_set_label(app->access_submit, "Review and allow access");
}

static GStrv access_arguments(App *app, GError **error)
{
    if (app->access_profile_invalid) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
            "Refresh system status and permissions to establish the firewall profile before allowing access.");
        return NULL;
    }
    const char *profile = app->access_edit_id != NULL ? app->access_edit_profile : selected_profile(app, app->access_profile);
    guint preset = gtk_drop_down_get_selected(app->access_preset);
    const char *ports = preset == 0 ? "80,443" : preset == 1 ? "22" : gtk_editable_get_text(app->access_ports);
    const char *protocol = preset != 2 || gtk_drop_down_get_selected(app->access_protocol) == 0 ? "tcp" : "udp";
    const char *source = NULL;
    const char *interface = NULL;
    guint scope = gtk_drop_down_get_selected(app->access_scope);
    if (scope == 0) {
        guint index = gtk_drop_down_get_selected(app->access_network);
        if (app->connections_loaded && app->lan_options != NULL && index < app->lan_options->len) {
            LanOption *network = g_ptr_array_index(app->lan_options, index);
            source = network->source; interface = network->interface;
        }
    } else if (scope == 1) {
        source = gtk_editable_get_text(app->access_source);
        interface = gtk_editable_get_text(app->access_interface);
    } else if (scope == 2) { source = "any"; interface = "any"; }
    static const char *const durations[] = {"30", "60", "240", "0"};
    guint duration = gtk_drop_down_get_selected(app->access_duration);
    if (profile == NULL || source == NULL || *source == '\0' || interface == NULL || *interface == '\0' ||
        *ports == '\0' || duration >= G_N_ELEMENTS(durations)) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
            "Select a detected local network, or enter a specific source and interface under Custom scope. Choose the service and duration before continuing.");
        return NULL;
    }
    GPtrArray *args = g_ptr_array_new();
    g_ptr_array_add(args, g_strdup("access"));
    g_ptr_array_add(args, g_strdup(app->access_edit_id != NULL ? "update" : "allow"));
    g_ptr_array_add(args, g_strdup(profile));
    if (app->access_edit_id != NULL) g_ptr_array_add(args, g_strdup(app->access_edit_id));
    g_ptr_array_add(args, g_strdup(ports)); g_ptr_array_add(args, g_strdup(protocol));
    g_ptr_array_add(args, g_strdup(source)); g_ptr_array_add(args, g_strdup(interface));
    g_ptr_array_add(args, g_strdup(durations[duration])); g_ptr_array_add(args, NULL);
    return (GStrv)g_ptr_array_free(args, FALSE);
}

static void access_allow_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    g_autoptr(GError) error = NULL;
    g_auto(GStrv) args = access_arguments(app, &error);
    if (args == NULL) { show_error(app, "Choose the access scope", error->message); return; }
    start_action(app, app->access_edit_id != NULL ? "Update network access" : "Allow network access",
        "Review the exact ports, source network, interface and duration before applying. Docker-published services require their separate forwarding review. A subnet does not authenticate a network; revoke this permission before changing networks.",
        TRUE, TRUE, g_strv_length(args), (const char *const *)args);
}

static void access_revoke_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    AccessRule *binding = data;
    const char *args[] = {"access", "revoke", string_member(binding->rule, "profile", ""), string_member(binding->rule, "id", "")};
    start_action(binding->app, "Revoke network access", "Remove this permission and apply the firewall change immediately after review. Other permissions remain in place.", TRUE, TRUE, G_N_ELEMENTS(args), args);
}

static void access_edit_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    AccessRule *binding = data;
    App *app = binding->app;
    g_free(app->access_edit_id); app->access_edit_id = g_strdup(string_member(binding->rule, "id", ""));
    g_free(app->access_edit_profile); app->access_edit_profile = g_strdup(string_member(binding->rule, "profile", ""));
    gtk_drop_down_set_selected(app->access_preset, 2);
    gtk_drop_down_set_selected(app->access_scope, 1);
    gtk_editable_set_text(app->access_ports, string_member(binding->rule, "ports", ""));
    gtk_editable_set_text(app->access_source, string_member(binding->rule, "source", ""));
    gtk_editable_set_text(app->access_interface, string_member(binding->rule, "interface", ""));
    gtk_drop_down_set_selected(app->access_protocol, g_str_equal(string_member(binding->rule, "protocol", "tcp"), "udp") ? 1 : 0);
    gtk_label_set_text(app->access_editing, "Editing the selected permission. Choose its new scope and duration, then review the replacement. Cancel edit leaves it unchanged.");
    gtk_button_set_label(app->access_submit, "Review and update access");
    gtk_widget_grab_focus(GTK_WIDGET(app->access_ports));
}

static gboolean show_access(App *app, JsonObject *root)
{
    JsonArray *rules = array_member(root, "rules");
    if (app->access_rules == NULL || rules == NULL || json_array_get_length(rules) > 256) return FALSE;
    const char *profile = string_member(root, "profile", "unmanaged");
    guint profile_index = GTK_INVALID_LIST_POSITION;
    for (guint i = 0; i < app->profile_ids->len; i++)
        if (g_str_equal(g_ptr_array_index(app->profile_ids, i), profile)) profile_index = i;
    if (profile_index == GTK_INVALID_LIST_POSITION) {
        app->access_profile_invalid = TRUE;
        access_cancel_edit(NULL, app);
        clear_list(app->access_rules);
        app->access_loaded = FALSE;
        gtk_label_set_text(app->access_summary, "The inspected firewall profile is missing from the current profile list. Refresh system status and permissions before continuing.");
        return FALSE;
    }
    gtk_drop_down_set_selected(app->access_profile, profile_index);
    app->access_profile_invalid = FALSE;
    g_autofree gchar *summary = octoshield_text_sanitize(string_member(root, "summary", "Review the permissions and their observed state below."), -1);
    gtk_label_set_text(app->access_summary, summary);
    clear_list(app->access_rules);
    for (guint i = 0; i < json_array_get_length(rules); i++) {
        JsonNode *node = json_array_get_element(rules, i);
        if (!JSON_NODE_HOLDS_OBJECT(node)) continue;
        JsonObject *rule = json_node_get_object(node);
        const char *id = string_member(rule, "id", "");
        if (!g_regex_match_simple("^[a-zA-Z0-9-]{1,96}$", id, 0, 0)) continue;
        GtkWidget *row = adw_action_row_new();
        adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
        g_autofree gchar *label = octoshield_text_sanitize(string_member(rule, "label", "Incoming access"), -1);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), label);
        const char *state = string_member(rule, "state", "unknown");
        const char *state_label = g_str_equal(state, "active") ? "Active" : g_str_equal(state, "pending") ? "Saved, not active" : g_str_equal(state, "expired") ? "Expired" : g_str_equal(state, "failed") ? "Apply failed" : "Not verified";
        gint64 expires = json_object_has_member(rule, "expires_at") ? json_object_get_int_member(rule, "expires_at") : 0;
        g_autoptr(GDateTime) when = expires > 0 ? g_date_time_new_from_unix_local(expires) : NULL;
        g_autofree gchar *expiry = when != NULL ? g_date_time_format(when, "%a %H:%M") : g_strdup("Until revoked");
        g_autofree gchar *raw = g_strdup_printf("%s · %s/%s · From %s on %s\n%s", state_label, string_member(rule, "ports", "?"), string_member(rule, "protocol", "?"), string_member(rule, "source", "?"), string_member(rule, "interface", "?"), expiry);
        g_autofree gchar *subtitle = octoshield_text_sanitize(raw, -1);
        adw_action_row_set_subtitle(ADW_ACTION_ROW(row), subtitle);
        adw_action_row_set_subtitle_lines(ADW_ACTION_ROW(row), 3);
        AccessRule *binding = g_new0(AccessRule, 1);
        binding->app = app; binding->rule = json_object_ref(rule);
        json_object_set_string_member(binding->rule, "profile", profile);
        g_object_set_data_full(G_OBJECT(row), "access-rule", binding, access_rule_free);
        GtkWidget *edit = gtk_button_new_with_label("Edit");
        GtkWidget *revoke = gtk_button_new_with_label("Revoke");
        gtk_widget_set_valign(edit, GTK_ALIGN_CENTER); gtk_widget_set_valign(revoke, GTK_ALIGN_CENTER);
        g_signal_connect(edit, "clicked", G_CALLBACK(access_edit_clicked), binding);
        g_signal_connect(revoke, "clicked", G_CALLBACK(access_revoke_clicked), binding);
        adw_action_row_add_suffix(ADW_ACTION_ROW(row), edit); adw_action_row_add_suffix(ADW_ACTION_ROW(row), revoke);
        gtk_list_box_append(app->access_rules, row);
    }
    if (json_array_get_length(rules) == 0) gtk_list_box_append(app->access_rules, text_label("No saved permissions in this firewall profile.", "dim-label"));
    app->access_loaded = TRUE;
    return TRUE;
}

static JsonObject *selected_connection(App *app)
{
    guint index = gtk_drop_down_get_selected(app->privacy_connection);
    return app->connection_data != NULL && index < json_array_get_length(app->connection_data) ? json_array_get_object_element(app->connection_data, index) : NULL;
}

static void privacy_selected(GObject *object, GParamSpec *property, gpointer data)
{
    (void)object; (void)property;
    App *app = data;
    JsonObject *connection = selected_connection(app);
    if (connection == NULL) {
        gtk_drop_down_set_selected(app->privacy_autoconnect, 2);
        gtk_drop_down_set_selected(app->privacy_discovery, 2);
        gtk_drop_down_set_selected(app->privacy_mac, 2);
        gtk_label_set_text(app->privacy_source, "Select a connection to see its configuration sources.");
        gtk_widget_set_visible(app->privacy_mac_row, FALSE);
        return;
    }
    const char *type = string_member(connection, "type", "");
    gtk_widget_set_visible(app->privacy_mac_row, g_str_equal(type, "wifi") || g_str_equal(type, "802-11-wireless"));
    const char *autoconnect = string_member(connection, "autoconnect", "unknown");
    gtk_drop_down_set_selected(app->privacy_autoconnect, g_str_equal(autoconnect, "yes") ? 0 : g_str_equal(autoconnect, "no") ? 1 : 2);
    const char *mdns = string_member(connection, "mdns", "");
    const char *llmnr = string_member(connection, "llmnr", "");
    gtk_drop_down_set_selected(app->privacy_discovery, g_str_equal(mdns, "2") && g_str_equal(llmnr, "2") ? 0 : g_str_equal(mdns, "0") && g_str_equal(llmnr, "0") ? 1 : 2);
    const char *mac = string_member(connection, "mac", "");
    gtk_drop_down_set_selected(app->privacy_mac, g_str_equal(mac, "stable") ? 0 : g_str_equal(mac, "permanent") ? 1 : 2);
    JsonObject *runtime = object_member(connection, "runtime");
    g_autofree gchar *summary = octoshield_text_sanitize(string_member(runtime, "summary", "Active connection privacy has not been verified."), -1);
    g_autofree gchar *coverage = g_strdup_printf("%s%s", summary, app->connections_incomplete ? "\nSome connections could not be inspected. Refresh to retry; the list may be incomplete." : "");
    gtk_label_set_text(app->privacy_summary, coverage);
    GString *sources = g_string_new("Configuration sources");
    JsonArray *files = array_member(connection, "source_files");
    for (guint i = 0; files != NULL && i < MIN(json_array_get_length(files), 16U); i++) {
        JsonNode *node = json_array_get_element(files, i);
        if (JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == G_TYPE_STRING) g_string_append_printf(sources, "\n%s", json_node_get_string(node));
    }
    if (files == NULL || json_array_get_length(files) == 0) g_string_append(sources, "\nNo persistent connection file was identified.");
    g_autofree gchar *safe = octoshield_text_sanitize(sources->str, -1);
    gtk_label_set_text(app->privacy_source, safe); g_string_free(sources, TRUE);
}

static gboolean show_connections(App *app, JsonObject *root)
{
    JsonArray *connections = array_member(root, "connections");
    if (connections == NULL || json_array_get_length(connections) > 256 || app->privacy_connection == NULL) return FALSE;
    app->connections_incomplete = boolean_member(root, "incomplete");
    g_autofree gchar *selected = g_strdup(string_member(selected_connection(app), "uuid", ""));
    g_clear_pointer(&app->connection_data, json_array_unref);
    app->connection_data = json_array_new();
    g_clear_pointer(&app->lan_options, g_ptr_array_unref);
    app->lan_options = g_ptr_array_new_with_free_func(lan_option_free);
    GtkStringList *names = gtk_string_list_new(NULL);
    GtkStringList *networks = gtk_string_list_new(NULL);
    guint selected_index = GTK_INVALID_LIST_POSITION;
    for (guint i = 0; i < json_array_get_length(connections); i++) {
        JsonNode *node = json_array_get_element(connections, i);
        if (!JSON_NODE_HOLDS_OBJECT(node)) continue;
        JsonObject *connection = json_node_get_object(node);
        const char *uuid = string_member(connection, "uuid", "");
        if (!g_regex_match_simple("^[a-fA-F0-9-]{36}$", uuid, 0, 0)) continue;
        gboolean active = boolean_member(connection, "active");
        g_autofree gchar *raw = g_strdup_printf("%.100s%s", string_member(connection, "name", "Saved connection"), active ? " · connected" : "");
        g_autofree gchar *name = octoshield_text_sanitize(raw, -1);
        gtk_string_list_append(names, name);
        guint index = json_array_get_length(app->connection_data);
        if (g_str_equal(uuid, selected) || (selected_index == GTK_INVALID_LIST_POSITION && active)) selected_index = index;
        json_array_add_object_element(app->connection_data, json_object_ref(connection));
        if (!active || !boolean_member(connection, "lan_candidate")) continue;
        JsonArray *subnets = array_member(connection, "subnets");
        for (guint j = 0; subnets != NULL && j < MIN(json_array_get_length(subnets), 16U); j++) {
            JsonNode *subnet = json_array_get_element(subnets, j);
            if (!JSON_NODE_HOLDS_VALUE(subnet) || json_node_get_value_type(subnet) != G_TYPE_STRING) continue;
            LanOption *option = g_new0(LanOption, 1);
            option->source = g_strdup(json_node_get_string(subnet));
            option->interface = g_strdup(string_member(connection, "interface", ""));
            option->label = g_strdup_printf("%s · %s · %s", name, option->source, option->interface);
            gtk_string_list_append(networks, option->label); g_ptr_array_add(app->lan_options, option);
        }
    }
    gtk_drop_down_set_model(app->privacy_connection, G_LIST_MODEL(names));
    gtk_drop_down_set_selected(app->privacy_connection, selected_index == GTK_INVALID_LIST_POSITION && json_array_get_length(app->connection_data) > 0 ? 0 : selected_index);
    /* GTK versions differ in whether a nonempty dropdown can be unselected.
     * A real placeholder keeps ambiguous scopes outside the valid indices. */
    if (app->lan_options->len != 1) gtk_string_list_append(networks, app->lan_options->len == 0 ? "No local network detected" : "Choose a local network…");
    gtk_drop_down_set_model(app->access_network, G_LIST_MODEL(networks));
    gtk_drop_down_set_selected(app->access_network, app->lan_options->len == 1 ? 0 : app->lan_options->len);
    adw_action_row_set_subtitle(ADW_ACTION_ROW(app->access_network_row), app->lan_options->len == 0 ? "No active physical Wi-Fi or Ethernet subnet was detected. Connect to your local network and refresh, or enter a custom scope." :
        app->lan_options->len == 1 ? "This subnet and incoming interface limit the permission. The network itself is not authenticated." : "Several subnets are connected. Choose which subnet's devices may connect; the permission does not include the others.");
    g_object_unref(names); g_object_unref(networks);
    if (json_array_get_length(app->connection_data) == 0) gtk_label_set_text(app->privacy_summary, "No supported saved connections were found. See operation details for inspection errors.");
    else privacy_selected(NULL, NULL, app);
    app->connections_loaded = TRUE;
    return TRUE;
}

static void privacy_save_clicked(GtkButton *button, gpointer data)
{
    App *app = data;
    JsonObject *connection = selected_connection(app);
    const char *key = g_object_get_data(G_OBJECT(button), "privacy-key");
    GtkDropDown *choice = g_str_equal(key, "autoconnect") ? app->privacy_autoconnect : g_str_equal(key, "discovery") ? app->privacy_discovery : app->privacy_mac;
    guint index = gtk_drop_down_get_selected(choice);
    if (!app->connections_loaded || connection == NULL || index > 1) { show_error(app, "Choose a connection and setting", "Refresh connections, select a saved network by name and choose the intended value before saving."); return; }
    const char *value = g_str_equal(key, "mac") ? (index == 0 ? "stable" : "permanent") : (index == 0 ? "true" : "false");
    const char *args[] = {"connections", "set", string_member(connection, "uuid", ""), key, value};
    start_action(app, "Save connection privacy", g_str_equal(key, "autoconnect") ?
        "Save the selected network's automatic-connection preference. No reconnect is required. NetworkManager decides when an eligible connection activates automatically." :
        "Review this connection's saved privacy setting. Reconnect separately when ready to activate discovery or address changes.", TRUE, TRUE, G_N_ELEMENTS(args), args);
}

static void privacy_reconcile_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    const char *args[] = {"connections", "reconcile"};
    start_action(app, "Review external network changes", "Compare current saved NetworkManager settings with OctoShield's record. Accepting changes updates tracking only and retains the original recovery baseline.", TRUE, TRUE, G_N_ELEMENTS(args), args);
}

static void privacy_reconnect_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    JsonObject *connection = selected_connection(app);
    if (!app->connections_loaded || connection == NULL) { show_error(app, "Select a connection", "Refresh and choose the saved network to reconnect."); return; }
    const char *args[] = {"connections", "reconnect", string_member(connection, "uuid", "")};
    start_action(app, "Reconnect selected network", "Reconnecting can briefly interrupt downloads, calls and remote sessions. The helper will confirm the selected connection before continuing.", TRUE, TRUE, G_N_ELEMENTS(args), args);
}

static void build_privacy(App *app)
{
    GtkWidget *page = page_new(app, "privacy", "Connection privacy", "Choose a saved network by name. Inspect current settings, make a focused change and reconnect when convenient.");
    GtkWidget *group = group_new(page, "Your connections", "Saved policy and the active connection are shown separately. Local discovery advertises names; firewall permissions decide incoming access.");
    app->privacy_connection = GTK_DROP_DOWN(gtk_drop_down_new(NULL, NULL));
    bound_dropdown(app->privacy_connection);
    g_ptr_array_add(app->operation_widgets, app->privacy_connection);
    group_add(group, control_row("Connection", NULL, GTK_WIDGET(app->privacy_connection)));
    group_add(group, control_row("Refresh saved and active settings", NULL, managed_button(app, "Refresh connections", G_CALLBACK(connections_refresh_clicked))));
    app->privacy_summary = GTK_LABEL(text_label("Refresh connections to inspect your networks.", "dim-label"));
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->privacy_summary));
    group = group_new(page, "Privacy choices", "Each Save changes only the selected connection after review. Private MAC addresses can affect networks that register your device address.");
    app->privacy_autoconnect = GTK_DROP_DOWN(gtk_drop_down_new_from_strings((const char *const[]){"Connect automatically", "Connect manually", "Other / unknown · choose…", NULL}));
    app->privacy_discovery = GTK_DROP_DOWN(gtk_drop_down_new_from_strings((const char *const[]){"Allow local name discovery", "Disable local name discovery", "Other / unknown · choose…", NULL}));
    app->privacy_mac = GTK_DROP_DOWN(gtk_drop_down_new_from_strings((const char *const[]){"Private stable address", "Hardware address", "Other / unknown · choose…", NULL}));
    GtkDropDown *choices[] = {app->privacy_autoconnect, app->privacy_discovery, app->privacy_mac};
    static const char *const keys[] = {"autoconnect", "discovery", "mac"};
    static const char *const names[] = {"Automatic connection", "Local discovery · mDNS / LLMNR", "Wi-Fi MAC address"};
    for (guint i = 0; i < G_N_ELEMENTS(choices); i++) {
        gtk_drop_down_set_selected(choices[i], 2);
        g_ptr_array_add(app->operation_widgets, choices[i]);
        GtkWidget *controls = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_append(GTK_BOX(controls), GTK_WIDGET(choices[i]));
        GtkWidget *save = managed_button(app, "Save", G_CALLBACK(privacy_save_clicked));
        g_object_set_data(G_OBJECT(save), "privacy-key", (gpointer)keys[i]);
        gtk_box_append(GTK_BOX(controls), save);
        GtkWidget *row = control_row(names[i], NULL, controls);
        if (i == 2) app->privacy_mac_row = row;
        group_add(group, row);
    }
    group_add(group, control_row("Apply saved settings to this connection", "Network access may pause briefly. Review the reconnect before continuing.", managed_button(app, "Reconnect…", G_CALLBACK(privacy_reconnect_clicked))));
    group_add(group, control_row("Review external changes", "Resolve differences blocking a whole-profile apply or restore. Review the actual settings before accepting them.", managed_button(app, "Review…", G_CALLBACK(privacy_reconcile_clicked))));
    app->privacy_source = GTK_LABEL(text_label("Configuration sources appear after inspection.", "dim-label"));
    gtk_label_set_selectable(app->privacy_source, TRUE); gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->privacy_source));
    g_signal_connect(app->privacy_connection, "notify::selected", G_CALLBACK(privacy_selected), app);
}

static void container_plan_clicked(GtkButton *button, gpointer data)
{
    App *app = data;
    const char *id = g_object_get_data(G_OBJECT(button), "container-id");
    if (id == NULL || !g_regex_match_simple("^[a-f0-9]{64}$", id, 0, 0)) return;
    const char *args[] = {"containers", "plan", id};
    start_action(app, "Review container local access", "Inspect this Compose service using your normal user account. No files or containers change during this review.", FALSE, FALSE, G_N_ELEMENTS(args), args);
}

static void container_apply_clicked(GtkButton *button, gpointer data)
{
    (void)button;
    App *app = data;
    const char *id = string_member(app->container_plan, "id", "");
    const char *token = string_member(app->container_plan, "token", "");
    if (!g_regex_match_simple("^[a-f0-9]{64}$", id, 0, 0) || !g_regex_match_simple("^[a-f0-9]{64}$", token, 0, 0)) return;
    const char *args[] = {"containers", "localize", id, token};
    start_action(app, "Restrict container to this computer", string_member(app->container_plan, "summary", "Apply the reviewed localhost binding and recreate only this service. Connections to it may be interrupted."), FALSE, TRUE, G_N_ELEMENTS(args), args);
}

static gboolean show_container_plan(App *app, JsonObject *root)
{
    const char *id = string_member(root, "id", "");
    const char *token = string_member(root, "token", "");
    if (!g_regex_match_simple("^[a-f0-9]{64}$", id, 0, 0) || !g_regex_match_simple("^[a-f0-9]{64}$", token, 0, 0)) return FALSE;
    g_clear_pointer(&app->container_plan, json_object_unref);
    app->container_plan = json_object_ref(root);
    clear_list(app->diagnostics_findings);
    g_autofree gchar *title = octoshield_text_sanitize(string_member(root, "title", "Restrict this service to your computer"), -1);
    g_autofree gchar *summary = octoshield_text_sanitize(string_member(root, "summary", "Review the exact source and affected service."), -1);
    gtk_label_set_text(app->diagnostics_title, title); gtk_label_set_text(app->diagnostics_summary, summary);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 16); gtk_widget_set_margin_bottom(box, 16); gtk_widget_set_margin_start(box, 16); gtk_widget_set_margin_end(box, 16);
    static const char *const fields[][2] = {{"service", "Affected service"}, {"override_path", "Local access override"}, {"snapshot_path", "Private recovery snapshot"}, {"command", "Recreation command"}, {"warning", "Before applying"}};
    for (guint i = 0; i < G_N_ELEMENTS(fields); i++) {
        const char *value = string_member(root, fields[i][0], "");
        if (*value == '\0') continue;
        gtk_box_append(GTK_BOX(box), text_label(fields[i][1], "heading"));
        g_autofree gchar *safe = octoshield_text_sanitize(value, -1);
        GtkWidget *label = text_label(safe, NULL); gtk_label_set_selectable(GTK_LABEL(label), TRUE); gtk_box_append(GTK_BOX(box), label);
    }
    JsonArray *sources = array_member(root, "sources");
    if (sources != NULL) {
        gtk_box_append(GTK_BOX(box), text_label("Original Compose files", "heading"));
        for (guint i = 0; i < MIN(json_array_get_length(sources), 16U); i++) {
            JsonNode *node = json_array_get_element(sources, i);
            if (!JSON_NODE_HOLDS_VALUE(node) || json_node_get_value_type(node) != G_TYPE_STRING) continue;
            g_autofree gchar *safe = octoshield_text_sanitize(json_node_get_string(node), -1);
            GtkWidget *label = text_label(safe, NULL); gtk_label_set_selectable(GTK_LABEL(label), TRUE); gtk_box_append(GTK_BOX(box), label);
        }
    }
    JsonArray *ports = array_member(root, "ports");
    if (ports != NULL) {
        gtk_box_append(GTK_BOX(box), text_label("Published ports become local-only", "heading"));
        for (guint i = 0; i < MIN(json_array_get_length(ports), 64U); i++) {
            JsonNode *node = json_array_get_element(ports, i);
            if (!JSON_NODE_HOLDS_OBJECT(node)) continue;
            JsonObject *port = json_node_get_object(node);
            JsonNode *target_node = json_object_get_member(port, "target");
            JsonNode *published_node = json_object_get_member(port, "published");
            g_autofree gchar *target = target_node != NULL && JSON_NODE_HOLDS_VALUE(target_node) && json_node_get_value_type(target_node) == G_TYPE_INT64 ? g_strdup_printf("%" G_GINT64_FORMAT, json_node_get_int(target_node)) : g_strdup(string_member(port, "target", "?"));
            g_autofree gchar *published = published_node != NULL && JSON_NODE_HOLDS_VALUE(published_node) && json_node_get_value_type(published_node) == G_TYPE_INT64 ? g_strdup_printf("%" G_GINT64_FORMAT, json_node_get_int(published_node)) : g_strdup(string_member(port, "published", "?"));
            g_autofree gchar *raw = g_strdup_printf("%s:%s → container port %s/%s", string_member(port, "host_ip", "localhost"), published, target, string_member(port, "protocol", "tcp"));
            g_autofree gchar *safe = octoshield_text_sanitize(raw, -1);
            gtk_box_append(GTK_BOX(box), text_label(safe, NULL));
        }
    }
    GtkWidget *apply = gtk_button_new_with_label("Review and restrict to this computer");
    app->container_apply = apply;
    gtk_widget_add_css_class(apply, "suggested-action");
    g_signal_connect(apply, "clicked", G_CALLBACK(container_apply_clicked), app);
    gtk_box_append(GTK_BOX(box), apply); gtk_list_box_append(app->diagnostics_findings, box);
    return TRUE;
}

static gboolean show_diagnostics(App *app, JsonObject *root)
{
    JsonArray *findings = array_member(root, "findings");
    if (findings == NULL || json_array_get_length(findings) > 256) return FALSE;
    g_clear_pointer(&app->container_plan, json_object_unref);
    app->container_apply = NULL;
    g_autofree gchar *title = octoshield_text_sanitize(string_member(root, "title", "Protection details"), -1);
    g_autofree gchar *summary = octoshield_text_sanitize(string_member(root, "summary", "Review the observed evidence and next steps."), -1);
    gtk_label_set_text(app->diagnostics_title, title); gtk_label_set_text(app->diagnostics_summary, summary);
    clear_list(app->diagnostics_findings);
    for (guint i = 0; i < json_array_get_length(findings); i++) {
        JsonNode *node = json_array_get_element(findings, i);
        if (!JSON_NODE_HOLDS_OBJECT(node)) continue;
        JsonObject *finding = json_node_get_object(node);
        GtkWidget *row = adw_expander_row_new();
        adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
        g_autofree gchar *heading = octoshield_text_sanitize(string_member(finding, "title", "Observation"), -1);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), heading);
        const char *state = string_member(finding, "state", "unknown");
        adw_expander_row_set_subtitle(ADW_EXPANDER_ROW(row), g_str_equal(state, "active") ? "Verified within the stated scope" : g_str_equal(state, "partial") ? "Review the indicated exposure" : g_str_equal(state, "unsupported") ? "Not available on this system" : "Inspection limits or further review");
        GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
        gtk_widget_set_margin_top(content, 12); gtk_widget_set_margin_bottom(content, 16);
        gtk_widget_set_margin_start(content, 18); gtk_widget_set_margin_end(content, 18);
        static const char *const fields[] = {"detail", "source", "action"};
        static const char *const labels[] = {"What was found", "Configuration source", "Next step"};
        for (guint j = 0; j < G_N_ELEMENTS(fields); j++) {
            const char *value = string_member(finding, fields[j], "");
            if (*value == '\0') continue;
            gtk_box_append(GTK_BOX(content), text_label(labels[j], "heading"));
            g_autofree gchar *safe = octoshield_text_sanitize(value, -1);
            GtkWidget *label = text_label(safe, NULL); gtk_label_set_selectable(GTK_LABEL(label), TRUE);
            gtk_box_append(GTK_BOX(content), label);
        }
        const char *id = string_member(finding, "container_id", "");
        if (g_str_equal(string_member(finding, "fix", ""), "localize") && g_regex_match_simple("^[a-f0-9]{64}$", id, 0, 0)) {
            GtkWidget *button = gtk_button_new_with_label("Review local-only access…");
            g_object_set_data_full(G_OBJECT(button), "container-id", g_strdup(id), g_free);
            g_signal_connect(button, "clicked", G_CALLBACK(container_plan_clicked), app);
            gtk_box_append(GTK_BOX(content), button);
        }
        adw_expander_row_add_row(ADW_EXPANDER_ROW(row), content);
        adw_expander_row_set_expanded(ADW_EXPANDER_ROW(row), json_array_get_length(findings) <= 3);
        gtk_list_box_append(app->diagnostics_findings, row);
    }
    return TRUE;
}

static void build_diagnostics(App *app)
{
    GtkWidget *page = page_new(app, "diagnostics", "Details & fixes", "Inspect the evidence, locate configuration and review the precise next step. Coverage limits are stated explicitly.");
    GtkWidget *group = group_new(page, "Inspect an area", "Inspection does not change disk encryption, stop containers or disable forwarding.");
    static const char *const topics[][2] = {{"disk_encryption", "Storage encryption"}, {"containers", "Docker ports and configuration"}, {"forwarding", "Forwarding and firewall paths"}, {"network", "Connection privacy evidence"}};
    for (guint i = 0; i < G_N_ELEMENTS(topics); i++) {
        GtkWidget *button = managed_button(app, "Inspect", G_CALLBACK(review_status_clicked));
        g_object_set_data(G_OBJECT(button), "topic", (gpointer)topics[i][0]);
        g_object_set_data(G_OBJECT(button), "inspect-network", GINT_TO_POINTER(1));
        group_add(group, control_row(topics[i][1], NULL, button));
    }
    app->diagnostics_title = GTK_LABEL(text_label("Choose an area to inspect", "title-2"));
    app->diagnostics_summary = GTK_LABEL(text_label("Details are read through your unlocked administrator session. Configuration sources are not published in the public status cache.", "dim-label"));
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->diagnostics_title)); gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->diagnostics_summary));
    app->diagnostics_findings = GTK_LIST_BOX(gtk_list_box_new()); gtk_list_box_set_selection_mode(app->diagnostics_findings, GTK_SELECTION_NONE);
    gtk_widget_add_css_class(GTK_WIDGET(app->diagnostics_findings), "boxed-list"); gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->diagnostics_findings));
}

static void access_profile_changed(GObject *object, GParamSpec *property, gpointer data)
{
    (void)object; (void)property;
    App *app = data;
    if (app->operation != NULL) return;
    access_cancel_edit(NULL, app);
    clear_list(app->access_rules);
    app->access_loaded = FALSE;
    gtk_label_set_text(app->access_summary, "Refresh to inspect this profile's saved permissions and active state.");
    if (app->auth_required && administrator_ready(app)) queue_private_refresh(app, 1U);
}

static void build_office(App *app)
{
    GtkWidget *page = page_new(app, "office", "Access & exceptions", "Share only the service you need. Choose a service, a local network and a duration; review once to save and apply its permission.");
    GtkWidget *group = group_new(page, "Allow a service", "Your effective firewall profile is selected automatically. Incoming permissions do not start a server or control Docker's forwarded traffic.");
    app->access_profile = GTK_DROP_DOWN(profile_selector(app));
    gtk_drop_down_set_selected(app->access_profile, GTK_INVALID_LIST_POSITION);
    group_add(group, control_row("Firewall profile", "Use Profiles & protection to change the active assignment.", GTK_WIDGET(app->access_profile)));
    group_add(group, control_row("Current permissions and connected networks", NULL, managed_button(app, "Refresh", G_CALLBACK(access_refresh_clicked))));
    app->access_preset = GTK_DROP_DOWN(gtk_drop_down_new_from_strings((const char *const[]){"Web server · HTTP + HTTPS", "Incoming SSH", "Custom ports…", NULL}));
    group_add(group, control_row("What would you like to share?", NULL, GTK_WIDGET(app->access_preset)));
    app->access_custom = group_new(page, "Custom service", "Enter one port or comma-separated ports. Each port receives the same scope and duration.");
    app->access_ports = GTK_EDITABLE(input_row(app->access_custom, "Ports · for example 8080,8443"));
    app->access_protocol = GTK_DROP_DOWN(gtk_drop_down_new_from_strings((const char *const[]){"TCP", "UDP", NULL}));
    group_add(app->access_custom, control_row("Protocol", NULL, GTK_WIDGET(app->access_protocol)));
    group = group_new(page, "Who may connect?", "Choose the network you trust. Subnets do not authenticate a network; revoke access before moving to an untrusted network.");
    app->access_scope = GTK_DROP_DOWN(gtk_drop_down_new_from_strings((const char *const[]){"Selected local network", "Specific address or subnet…", "Any network · unrestricted", NULL}));
    group_add(group, control_row("Access scope", NULL, GTK_WIDGET(app->access_scope)));
    app->access_network = GTK_DROP_DOWN(gtk_drop_down_new(NULL, NULL));
    bound_dropdown(app->access_network);
    app->access_network_row = control_row("Detected local network", "Physical Wi-Fi and Ethernet only. Choose explicitly when several networks are connected.", GTK_WIDGET(app->access_network));
    group_add(group, app->access_network_row);
    app->access_address = group_new(page, "Custom scope", "IPv4 and IPv6 addresses or CIDRs are supported. Enter an interface name, or explicitly use any.");
    app->access_source = GTK_EDITABLE(input_row(app->access_address, "Source address or subnet"));
    app->access_interface = GTK_EDITABLE(input_row(app->access_address, "Incoming interface"));
    group = group_new(page, "How long?", "Temporary access starts when you approve the change. It can end earlier on firewall reload or reboot; existing connections are not forcibly disconnected.");
    app->access_duration = GTK_DROP_DOWN(gtk_drop_down_new_from_strings((const char *const[]){"30 minutes", "1 hour", "4 hours", "Until I revoke it", NULL}));
    gtk_drop_down_set_selected(app->access_duration, 1);
    group_add(group, control_row("Permission duration", NULL, GTK_WIDGET(app->access_duration)));
    app->access_editing = GTK_LABEL(text_label("Choose what to share and who may connect. Localhost access needs no incoming firewall permission.", "dim-label"));
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->access_editing));
    GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(buttons, GTK_ALIGN_END);
    gtk_box_append(GTK_BOX(buttons), managed_button(app, "Cancel edit", G_CALLBACK(access_cancel_edit)));
    app->access_submit = GTK_BUTTON(managed_button(app, "Review and allow access", G_CALLBACK(access_allow_clicked)));
    gtk_widget_add_css_class(GTK_WIDGET(app->access_submit), "suggested-action");
    gtk_box_append(GTK_BOX(buttons), GTK_WIDGET(app->access_submit)); gtk_box_append(GTK_BOX(page), buttons);
    group = group_new(page, "Your permissions", "Edit or revoke a permission directly. An active firewall rule does not prove that the service is listening or reachable through every network path.");
    app->access_summary = GTK_LABEL(text_label("Refresh to inspect saved permissions and their observed state.", "dim-label"));
    group_add(group, GTK_WIDGET(app->access_summary));
    app->access_rules = GTK_LIST_BOX(gtk_list_box_new()); gtk_list_box_set_selection_mode(app->access_rules, GTK_SELECTION_NONE);
    gtk_widget_add_css_class(GTK_WIDGET(app->access_rules), "boxed-list"); gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->access_rules));
    GtkWidget *fields[] = {GTK_WIDGET(app->access_preset), GTK_WIDGET(app->access_scope), GTK_WIDGET(app->access_network), GTK_WIDGET(app->access_protocol), GTK_WIDGET(app->access_duration), GTK_WIDGET(app->access_ports), GTK_WIDGET(app->access_source), GTK_WIDGET(app->access_interface)};
    for (guint i = 0; i < G_N_ELEMENTS(fields); i++) g_ptr_array_add(app->operation_widgets, fields[i]);
    g_signal_connect(app->access_preset, "notify::selected", G_CALLBACK(access_choices_changed), app);
    g_signal_connect(app->access_scope, "notify::selected", G_CALLBACK(access_choices_changed), app);
    g_signal_connect(app->access_profile, "notify::selected", G_CALLBACK(access_profile_changed), app);
    access_choices_changed(NULL, NULL, app);
    group = group_new(page, "Restore a service", "Starting a listening service and allowing its firewall traffic are separate decisions.");
    static const char *const services[] = {"SSH · ssh.service", "Local discovery · avahi-daemon.service", "Bluetooth · bluetooth.service", "Printing · cups.service", NULL};
    GtkWidget *service = gtk_drop_down_new_from_strings(services);
    group_add(group, control_row("Service", NULL, service));
    gtk_box_append(GTK_BOX(page), input_button(app, "Restore service…", INPUT_OFFICE_SERVICE, NULL, NULL, NULL, service));
}

static void build_monitoring(App *app)
{
    GtkWidget *page = page_new(app, "monitoring", "Security monitoring", "See meaningful activity from existing system security events, with restrained notifications in your GNOME session.");
    GtkWidget *group = group_new(page, "System event collector", "Collects repeated firewall blocks, trusted authentication failures and USBGuard denials. Passive network sniffing cannot reliably be detected from the laptop.");
    group_add(group, action_row(app, "monitor", "Enable…", "network-transmit-receive-symbolic"));
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
    GtkWidget *page = page_new(app, "recovery", "Recovery, updates & change records", "Restore recorded settings with an explicit preview. Updates install over the existing Debian package and retain your saved configuration.");
    GtkWidget *group = group_new(page, "Restore system settings", "Restore the baseline recorded before profile management. The helper previews changes and reports any incomplete recovery.");
    group_add(group, control_row("Previous system settings", NULL, profile_button(app, "Restore…", PROFILE_RESTORE, NULL, NULL, NULL, NULL, NULL)));
    group = group_new(page, "OctoShield updates", "Download the Debian package for your Ubuntu version, then open it with the system installer. Administrator authentication is handled by the package manager.");
    group_add(group, action_row(app, "update-check", "Check", "software-update-available-symbolic"));
    app->update_status = GTK_LABEL(text_label("Installed " OCTOSHIELD_VERSION ". Check when you are ready; opening this app does not contact the repository.", "dim-label"));
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->update_status));
    app->update_link = GTK_LINK_BUTTON(gtk_link_button_new_with_label("https://github.com/octoleo/octoshield/releases/latest", "Download the latest Debian package"));
    gtk_widget_set_halign(GTK_WIDGET(app->update_link), GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(page), GTK_WIDGET(app->update_link));
    group = group_new(page, "Recovery information", "System configuration backups remain administrator-only. The detail view shows a transaction's action record, not stored configuration secrets.");
    group_add(group, action_row(app, "recovery", "Read", "help-browser-symbolic"));
    group_add(group, action_row(app, "backups", "List", "document-open-recent-symbolic"));
    GtkWidget *transaction = input_row(group, "Backup transaction ID · copy from the backup list");
    gtk_box_append(GTK_BOX(page), input_button(app, "Inspect transaction", INPUT_BACKUP_SHOW, transaction, NULL, NULL, NULL));
    group = group_new(page, "Restore your desktop baseline", "This restores the original recorded GNOME preferences; use Access & exceptions for narrow system exceptions.");
    group_add(group, action_row(app, "desktop-restore", "Restore…", "edit-undo-symbolic"));
    gtk_box_append(GTK_BOX(page), text_label("If a system operation fails after an earlier step completed, some changes may already be in effect. Keep the operation details and inspect the recorded transaction before retrying or recovering.", "dim-label"));
}

static void navigation_selected(GtkListBox *list, GtkListBoxRow *row, gpointer data)
{
    (void)list;
    App *app = data;
    if (row != NULL) {
        const char *page = g_object_get_data(G_OBJECT(row), "page-name");
        gtk_stack_set_visible_child_name(app->pages, page);
        if (app->auth_required && administrator_ready(app)) {
            if (g_str_equal(page, "office")) queue_private_refresh(app, 3U);
            else if (g_str_equal(page, "privacy")) queue_private_refresh(app, 2U);
        }
    }
}

static GtkWidget *build_sidebar(App *app)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_size_request(box, 208, -1);
    gtk_widget_add_css_class(box, "shield-sidebar");
    GtkWidget *brand = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_start(brand, 18);
    gtk_widget_set_margin_top(brand, 22);
    gtk_widget_set_margin_bottom(brand, 15);
    gtk_box_append(GTK_BOX(brand), brand_widget(app, 40, 46));
    gtk_box_append(GTK_BOX(brand), text_label("OctoShield", "title-3"));
    gtk_box_append(GTK_BOX(box), brand);
    GtkWidget *list = gtk_list_box_new();
    app->navigation = GTK_LIST_BOX(list);
    gtk_widget_add_css_class(list, "navigation-sidebar");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    static const char *const navigation[][3] = {
        {"overview", "Overview", "view-grid-symbolic"},
        {"protections", "Profiles & protection", "security-high-symbolic"},
        {"usb", "USB devices", "drive-removable-media-symbolic"},
        {"office", "Access & exceptions", "network-workgroup-symbolic"},
        {"privacy", "Connection privacy", "network-wireless-symbolic"},
        {"diagnostics", "Details & fixes", "dialog-information-symbolic"},
        {"monitoring", "Monitoring", "network-transmit-receive-symbolic"},
        {"recovery", "Recovery & updates", "edit-undo-symbolic"}
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
    GtkWidget *footer = text_label("Octoleo suite\nVast Development Method", "dim-label");
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
    app->activity = GTK_LABEL(text_label("Ready · status refreshes automatically; changes need your approval", "dim-label"));
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
    app->shutting_down = TRUE;
    session_revoke(app, "Closing the administrator session…");
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

static void refresh_session_services(void)
{
    /* Reload an already-running notifier after package upgrade. try-restart
     * preserves a user's choice to leave notifications disabled. The fixed
     * user-service invocation cannot request system privileges. */
    const char *const command[] = {"/usr/bin/systemctl", "--user", "try-restart", "octoshield-notify.service", NULL};
    GSubprocess *process = g_subprocess_newv(command, G_SUBPROCESS_FLAGS_STDOUT_SILENCE | G_SUBPROCESS_FLAGS_STDERR_SILENCE, NULL);
    if (process != NULL) g_subprocess_wait_async(process, NULL, accounts_waited, NULL);
    /* A package upgrade must not require logging out before USB dialogs work.
     * The agent enforces the user's automatic-prompts preference itself. */
    const char *const usb_command[] = {"/usr/bin/systemctl", "--user", "start", "octoshield-usb-agent.service", NULL};
    process = g_subprocess_newv(usb_command, G_SUBPROCESS_FLAGS_STDOUT_SILENCE | G_SUBPROCESS_FLAGS_STDERR_SILENCE, NULL);
    if (process != NULL) g_subprocess_wait_async(process, NULL, accounts_waited, NULL);
}

static void activate(GApplication *application, gpointer data)
{
    App *app = data;
    if (app->window != NULL) {
        gtk_window_present(app->window);
        refresh_status(app);
        maybe_prompt_usb(app);
        return;
    }
    app->window = GTK_WINDOW(adw_application_window_new(GTK_APPLICATION(application)));
    gtk_window_set_title(app->window, "OctoShield");
    gtk_window_set_default_size(app->window, 1100, 820);
    gtk_widget_set_size_request(GTK_WIDGET(app->window), 820, 600);
    g_signal_connect(app->window, "close-request", G_CALLBACK(window_close_requested), app);
    app->operation_widgets = g_ptr_array_new();
    app->status_rows = g_ptr_array_new_with_free_func(g_free);
    app->profile_selectors = g_ptr_array_new();
    app->profile_ids = g_ptr_array_new_with_free_func(g_free);
    app->usb_inventory_rows = g_ptr_array_new_with_free_func(usb_device_free);
    app->usb_decisions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    app->setting_choices = g_hash_table_new(g_str_hash, g_str_equal);
    app->usb_automatic = usb_automatic_preference();
    static const char *const defaults[] = {"conference", "public", "office", "home"};
    for (gsize i = 0; i < G_N_ELEMENTS(defaults); i++)
        g_ptr_array_add(app->profile_ids, g_strdup(defaults[i]));
    app->brand_pictures = g_ptr_array_new();
    app->style_manager = adw_style_manager_get_default();
    adw_style_manager_set_color_scheme(app->style_manager, ADW_COLOR_SCHEME_DEFAULT);
    app->theme_handler = g_signal_connect(app->style_manager, "notify::dark", G_CALLBACK(branding_changed), app);
    app->pages = GTK_STACK(gtk_stack_new());
    gtk_stack_set_transition_type(app->pages, GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_set_transition_duration(app->pages, 130);
    gtk_widget_set_vexpand(GTK_WIDGET(app->pages), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(app->pages), TRUE);
    app->toasts = ADW_TOAST_OVERLAY(adw_toast_overlay_new());
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *header = adw_header_bar_new();
    adw_header_bar_set_title_widget(ADW_HEADER_BAR(header), adw_window_title_new("OctoShield", "Laptop protection · Octoleo"));
    app->unlock = GTK_BUTTON(gtk_button_new_with_label("Unlock"));
    gtk_widget_set_tooltip_text(GTK_WIDGET(app->unlock), "Unlock once for this window; locking or closing ends administrator access");
    g_signal_connect(app->unlock, "clicked", G_CALLBACK(unlock_clicked), app);
    adw_header_bar_pack_start(ADW_HEADER_BAR(header), GTK_WIDGET(app->unlock));
    GtkWidget *about = gtk_button_new_from_icon_name("help-about-symbolic");
    gtk_widget_set_tooltip_text(about, "About OctoShield");
    gtk_accessible_update_property(GTK_ACCESSIBLE(about), GTK_ACCESSIBLE_PROPERTY_LABEL, "About OctoShield", -1);
    g_signal_connect(about, "clicked", G_CALLBACK(about_clicked), app);
    adw_header_bar_pack_end(ADW_HEADER_BAR(header), about);
    adw_header_bar_pack_end(ADW_HEADER_BAR(header), action_button(app, "status", "Inspect system", FALSE));
    gtk_box_append(GTK_BOX(outer), header);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    build_overview(app);
    build_protections(app);
    build_usb(app);
    build_office(app);
    build_privacy(app);
    build_diagnostics(app);
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
    app->access_pages = GTK_STACK(gtk_stack_new());
    gtk_widget_set_vexpand(GTK_WIDGET(app->access_pages), TRUE);
    gtk_stack_add_named(app->access_pages, body, "application");
    GtkWidget *locked = gtk_box_new(GTK_ORIENTATION_VERTICAL, 18);
    gtk_widget_set_halign(locked, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(locked, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(locked, 40); gtk_widget_set_margin_end(locked, 40);
    gtk_box_append(GTK_BOX(locked), text_label("Unlock OctoShield", "title-1"));
    app->access_status = GTK_LABEL(text_label("Authenticate once to manage protection in this window. Your desktop stays unprivileged; only approved system operations run through the administrator session.", NULL));
    gtk_label_set_max_width_chars(app->access_status, 65);
    gtk_box_append(GTK_BOX(locked), GTK_WIDGET(app->access_status));
    GtkWidget *unlock_main = gtk_button_new_with_label("Unlock with an administrator account");
    app->unlock_primary = GTK_BUTTON(unlock_main);
    gtk_widget_add_css_class(unlock_main, "suggested-action");
    g_signal_connect(unlock_main, "clicked", G_CALLBACK(unlock_clicked), app);
    gtk_box_append(GTK_BOX(locked), unlock_main);
    gtk_box_append(GTK_BOX(locked), text_label("Closing or locking this window ends access. Your existing firewall and USB policies remain in force.", "dim-label"));
    gtk_stack_add_named(app->access_pages, locked, "locked");
    gtk_box_append(GTK_BOX(outer), GTK_WIDGET(app->access_pages));
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
    refresh_status(app);
    app->refresh_timer = g_timeout_add_seconds(2, refresh_status, app);
    gtk_window_present(app->window);
    if (app->refresh_session_service && !app->smoke_test)
        refresh_session_services();
    if (app->auth_required && !app->smoke_test) {
        g_bus_get(G_BUS_TYPE_SYSTEM, NULL, login_bus_ready, app);
        if (!app->usb_review_launch) session_unlock(app);
    }
    if (app->smoke_test)
        g_timeout_add(700, smoke_finished, app);
}

static int application_command_line(GApplication *application, GApplicationCommandLine *command, gpointer data)
{
    App *app = data;
    int argc = 0;
    g_auto(GStrv) argv = g_application_command_line_get_arguments(command, &argc);
    if (argc > 2 || (argc == 2 && !g_str_equal(argv[1], "--usb-review"))) return 2;
    if (app->window == NULL) app->usb_review_launch = argc == 2;
    g_application_activate(application);
    return 0;
}

int main(int argc, char **argv)
{
    gboolean smoke_test = FALSE;
    if (argc == 2 && g_str_equal(argv[1], "--version")) {
        g_print("OctoShield %s\n", OCTOSHIELD_VERSION);
        return 0;
    }
    if (argc == 2 && g_str_equal(argv[1], "--help")) {
        g_print("Usage: octoshield-gtk [--version | --usb-review | --smoke-test]\n\nOpen OctoShield in your normal GNOME user session.\n--smoke-test opens a read-only window briefly for display tests.\n");
        return 0;
    }
    if (argc == 2 && g_str_equal(argv[1], "--smoke-test")) {
        smoke_test = TRUE;
        argc = 1;
    } else if (argc != 1 && !(argc == 2 && g_str_equal(argv[1], "--usb-review"))) {
        g_printerr("Unknown argument. Run octoshield-gtk --help.\n");
        return 2;
    }
    if (geteuid() == 0) {
        g_printerr("Run OctoShield as your normal GNOME user, without sudo. Administrator authentication unlocks this application session.\n");
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
    app.auth_required = !smoke_test;
    app.refresh_session_service = TRUE;
    app.application = adw_application_new(OCTOSHIELD_APPLICATION_ID, smoke_test ? G_APPLICATION_NON_UNIQUE : G_APPLICATION_HANDLES_COMMAND_LINE);
    g_signal_connect(app.application, "activate", G_CALLBACK(activate), &app);
    if (!smoke_test) g_signal_connect(app.application, "command-line", G_CALLBACK(application_command_line), &app);
    int result = g_application_run(G_APPLICATION(app.application), argc, argv);
    if (app.session != NULL) g_output_stream_close(app.session->input, NULL, NULL);
    g_clear_object(&app.login_session);
    branding_clear(&app);
    if (app.operation_widgets != NULL)
        g_ptr_array_unref(app.operation_widgets);
    g_object_unref(app.application);
    return result;
}
