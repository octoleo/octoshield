/* SPDX-License-Identifier: Apache-2.0 */
/* Exercise the actual GUI command model without starting GTK or a privileged
 * process. Each output line is one argv word, so shell parsing is never used. */
#include "protocol.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 3 || (strcmp(argv[1], "privileged") != 0 &&
                     strcmp(argv[1], "user") != 0)) {
        return 2;
    }
    GError *error = NULL;
    GStrv command = octoshield_action_argv(
        strcmp(argv[1], "privileged") == 0, (gsize)argc - 2,
        (const gchar *const *)(argv + 2), &error);
    if (command == NULL) {
        if (error != NULL) {
            fprintf(stderr, "%s\n", error->message);
        }
        g_clear_error(&error);
        return 2;
    }
    for (gsize index = 0; command[index] != NULL; index++) {
        puts(command[index]);
    }
    g_strfreev(command);
    return 0;
}
