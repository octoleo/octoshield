/* SPDX-License-Identifier: Apache-2.0 */
#ifndef OCTOSHIELD_UI_PROTOCOL_H
#define OCTOSHIELD_UI_PROTOCOL_H

#include <glib.h>

G_BEGIN_DECLS

#define OCTOSHIELD_EVENT_MAX_BYTES ((gsize)65536)
#define OCTOSHIELD_CONFIRM_MAX_ID ((guint64)G_MAXINT32)
#define OCTOSHIELD_PROTOCOL_ERROR (octoshield_protocol_error_quark())

typedef enum {
    OCTOSHIELD_PROTOCOL_ERROR_INVALID_EVENT,
    OCTOSHIELD_PROTOCOL_ERROR_TOO_LARGE,
    OCTOSHIELD_PROTOCOL_ERROR_INVALID_ACTION
} OctoshieldProtocolError;

typedef enum {
    OCTOSHIELD_EVENT_LOG,
    OCTOSHIELD_EVENT_CONFIRM,
    OCTOSHIELD_EVENT_DONE
} OctoshieldEventType;

typedef struct {
    OctoshieldEventType type;
    gchar *text;
    gboolean success;
    gboolean change_started_known;
    gboolean change_started;
    guint64 id;
} OctoshieldEvent;

GQuark octoshield_protocol_error_quark(void);

/* Parse one bounded JSONL record (optional final LF or CRLF). A negative length
 * of -1 means NUL-terminated input. Initialize event with {0}; clear each
 * successful result before reusing it. On failure event is left unchanged.
 * Text is owned by the event, sanitized for plain-text display, and must NEVER
 * be passed to a markup interpreter. Unknown fields are ignored for protocol
 * extensibility; required fields and their JSON types are checked strictly.
 * Completion may include boolean change_started; absence leaves its state
 * unknown, while false means no protection transaction was started.
 * Confirmations require an integer id in 1..OCTOSHIELD_CONFIRM_MAX_ID. Other
 * events have id zero. The caller must enforce increasing confirmation ids
 * within each helper process and include the id in every approval response. */
gboolean octoshield_event_parse(const gchar *line, gssize length,
                               OctoshieldEvent *event, GError **error);
void octoshield_event_clear(OctoshieldEvent *event);

/* Return an allocated, valid UTF-8 plain-text string. Invalid UTF-8 is replaced;
 * newline/tab are preserved for policy review. Other control characters,
 * carriage returns and bidi formatting characters become spaces.
 * length is a byte count, or -1 for NUL-terminated input. Free with g_free(). */
gchar *octoshield_text_sanitize(const gchar *text, gssize length);

/* Build a newly allocated, NULL-terminated argv from validated command words.
 * privileged selects a fixed pkexec/helper prefix; otherwise the fixed
 * octoshield user-api prefix is used. No shell or PATH lookup is involved.
 * The caller owns the returned vector and releases it with g_strfreev().
 * Rejection returns NULL and sets OCTOSHIELD_PROTOCOL_ERROR_INVALID_ACTION.
 * The backend must independently repeat validation at its trust boundary. */
GStrv octoshield_action_argv(gboolean privileged, gsize argc,
                           const gchar *const *args, GError **error);

G_END_DECLS

#endif
