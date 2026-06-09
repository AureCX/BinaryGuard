/*
** EPITECH PROJECT, 2026
** BinaryGuard
** File description:
** BinaryGuard utils
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

void my_array_free(int count, ...)
{
    char **ptr = NULL;
    va_list arrays;

    va_start(arrays, count);
    for (; count > 0; count--) {
        ptr = va_arg(arrays, char **);
        for (int i = 0; ptr && ptr[i] != NULL; i++) {
            free(ptr[i]);
            ptr[i] = NULL;
        }
        free(ptr);
        ptr = NULL;
    }
    va_end(arrays);
}

char *get_file_name(char *orig_file)
{
    int idx = 0;
    char *new = NULL;

    new = strrchr(orig_file, '/') + 1;
    if (new != (void *)0x1) {
        return new;
    } else
        return orig_file;
}

char *total_risk_color(int risk)
{
    if (risk < 25)
        return "\e[0;102m";
    else if (risk < 75)
        return "\e[0;103m";
    else
        return "\e[0;101m";
}

char *remove_file_extension(char *filename)
{
    char *new = NULL;

    for (int i = 0; filename[i]; ++i)
        if (filename[i] == '.') {
            new = strdup(filename);
            new[i] = '\0';
            return new;
        }
    return filename;
}