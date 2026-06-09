/*
** EPITECH PROJECT, 2026
** BinaryGuard
** File description:
** Main header file for BinaryGuard
*/

#ifndef BINARYGUARD_H
    #define BINARYGUARD_H

    #include <stdbool.h>
    #include <stdio.h>
    #define ERROR_MALLOC "Error: Malloc assertion failed!\n"

// UTILS

void my_array_free(int count, ...);
char *get_file_name(char *orig_file);
char *total_risk_color(int risk);
char *remove_file_extension(char *filename);

// TABLES AND STRUCTS

typedef enum {
    ELF,
    PE,
    MACH_O,
} bin_type_t;

typedef enum {
    CANARY_NONE,
    CANARY_LIKELY_USED,
    CANARY_SUPPORT,
} canary_type_t;

typedef struct binary_info_s {
    char *name;
    int total_risk;
    int type;

    bool is_pie;
    int canary_type;

    char **vulnerabilities;
    int vuln_count;

    int nb_potential_passwds;
} binary_info_t;

typedef struct dangerous_functions_s {
    char *symbol;
    char *name;
    char *description;
    int severity;
    int type;
} dangerous_functions_t;

typedef enum {
    BUFFER_OVERFLOWS,
    CMD_EXEC,
    FORMAT_STRING,
    MEMORY_SAFETY,
    IO_RISKS,
} vuln_types_t;

static const dangerous_functions_t vuln_table[] = {
    /* =========================
     * BUFFER OVERFLOWS
     * ========================= */
    {"gets", "Buffer Overflow",
     "Reads unlimited input into a fixed-size buffer. Removed from modern C standard.", 105, BUFFER_OVERFLOWS},
    {"strcpy", "Buffer Overflow",
     "Copies string without checking destination size.", 8, BUFFER_OVERFLOWS},
    {"strcat", "Buffer Overflow",
     "Appends string without bounds checking.", 8, BUFFER_OVERFLOWS},
    {"sprintf", "Buffer Overflow",
     "Formats data into buffer without size limit.", 9, BUFFER_OVERFLOWS},
    {"vsprintf", "Buffer Overflow",
     "Same as sprintf but with variadic arguments.", 9, BUFFER_OVERFLOWS},
    {"scanf", "Buffer Overflow",
     "Unsafe when using %%s without width limit specifier.", 7, BUFFER_OVERFLOWS},
    {"fscanf", "Buffer Overflow",
     "Unsafe when reading strings without field width limits.", 7, BUFFER_OVERFLOWS},
    /* =========================
     * COMMAND EXECUTION
     * ========================= */
    {"system", "Command Injection",
     "Executes shell commands directly. Dangerous if input is unsanitized.", 10, CMD_EXEC},
    {"popen", "Command Injection",
     "Runs shell command and returns pipe to process.", 9, CMD_EXEC},
    {"execve", "Command Execution",
     "Low-level process execution. Dangerous if arguments are user-controlled.", 8, CMD_EXEC},
    {"execl", "Command Execution",
     "Executes program with argument list. Risky with untrusted input.", 8, CMD_EXEC},
    {"execvp", "Command Execution",
     "Searches PATH for executable. Can be abused if input is controlled.", 8, CMD_EXEC},
    /* =========================
     * FORMAT STRING VULNERABILITIES
     * ========================= */
    {"sprintf", "Format String Risk",
     "Also listed under buffer overflow; dual risk depending on usage.", 8, FORMAT_STRING},
    {"snprintf", "Reduced Format Risk",
     "Safer alternative but still risky if misused, especially on some platforms where sprintf was called instead.", 3, FORMAT_STRING},
    /* =========================
     * MEMORY SAFETY ISSUES
     * ========================= */
    {"memcpy", "Memory Corruption Risk",
     "Unsafe if size is not validated.", 7, MEMORY_SAFETY},
    {"memmove", "Memory Corruption Risk",
     "Safer than memcpy but still depends on correct size usage.", 5, MEMORY_SAFETY},
    {"malloc", "Memory Allocation Risk",
     "Risk when size is based on untrusted input or when the result isn't checked.", 4, MEMORY_SAFETY},
    {"free", "Memory Management Risk",
     "Can lead to double-free or use-after-free if misused.", 6, MEMORY_SAFETY},
    /* =========================
     * FILE / IO RISKS
     * ========================= */
    {"fopen", "File Access Risk",
     "May allow path traversal if filename is user-controlled.", 5, IO_RISKS},
    {"open", "File Descriptor Risk",
     "Low-level file access; dangerous with unsanitized paths.", 5, IO_RISKS},
    {"remove", "File Deletion Risk",
     "Can delete arbitrary files if input is not validated.", 7, IO_RISKS},
    {"rename", "File Manipulation Risk",
     "May overwrite important files if misused.", 6, IO_RISKS},
    {(void *)0, (void *)0, (void *)0, -1, -1},
};

// BINARY STUFF

int binaryguard(int ac, char **av, char **env);
void elf_binary(char *buffer, binary_info_t *bin);
void write_json_report(FILE *f, binary_info_t *bin);

typedef struct bin_type_table_s {
    int bin_type;
    void (*fct)(char *, binary_info_t *);
} bin_type_table_t;

static const bin_type_table_t bin_table[] = {
    {ELF, elf_binary},
    {PE, (void *)0},
    {MACH_O, (void *)0},
    {-1, (void *)0},
};

#endif
