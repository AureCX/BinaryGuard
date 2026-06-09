/*
** EPITECH PROJECT, 2026
** BinaryGuard
** File description:
** BinaryGuard main file
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "binaryguard.h"

static void help(void)
{
    printf("BinaryGuard: The way to secure your apps and devices!\n\n");
    printf("How to use:\n");
    printf("./BinaryGuard [binary to test] ...\n\n");
    printf("Enter your desired binaries to test and the program will automatically\n");
    printf("and clearly show you the weak points of the binaries, and how to fix them,\n");
    printf("all of this without any experience!\n");
    exit(0);
}

static int analyze_binary(char *buffer, binary_info_t *bin)
{
    if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F') {
        bin->type = ELF;
        printf("ELF binary detected, continuing...\n");
    }
    for (int i = 0; bin_table[i].bin_type != -1; ++i)
        if (bin->type == bin_table[i].bin_type) {
            bin_table[i].fct(buffer, bin);
            return 0;
        }
    dprintf(2, "Error: Invalid file exec number, couldn't match.\n");
    return 1;
}

static char *get_binary_type(int type)
{
    switch(type) {
        case 0:
            return "ELF64";
        case 1:
            return "Windows EXE";
        case 2:
            return "MacOS EXE";
        default:
            return "Unspecified";
    };
}

static char *logo_for_protection(int presence)
{
    if (presence >= 1)
        return "✓";
    else
        return "✗";
}

static char *importance_level(int risk)
{
    if (risk <= 25)
        return "LOW";
    if (risk <= 50)
        return "MEDIUM";
    if (risk <= 75)
        return "HIGH";
    if (risk > 75)
        return "CRITICAL";
    else
        return "UNMEASURED";
}

static void write_report(FILE *f, binary_info_t *bin)
{
    fprintf(f, "BinaryGuard Security Report\n"
        "==================================================\n\n");
    fprintf(f, "Target      : %s\n"
        "Architecture: %s\n"
        "Risk Score  : %d/100 [%s]\n\n", bin->name, get_binary_type(bin->type), bin->total_risk, importance_level(bin->total_risk));
    fprintf(f, "Protections\n"
        "--------------------------------------------------\n"
        "[%s] PIE\n"
        "[%s] Canary\n"
        "[%s] NX\n\n", logo_for_protection(bin->is_pie), logo_for_protection(bin->canary_type), logo_for_protection(1));
    fprintf(f, "Detected Vulnerabilities\n"
        "--------------------------------------------------\n");
    if (bin->nb_potential_passwds > 0)
        fprintf(f, "[CRIT] Weak credential(s): %d\n", bin->nb_potential_passwds);
    for (int i = 0; bin->vulnerabilities && bin->vulnerabilities[i]; ++i)
        fprintf(f, "[HIGH] %s (1 call sites)\n", bin->vulnerabilities[i]);
    /*fprintf(f, "\nRecommendations\n"
        "--------------------------------------------------\n"
        "1. Replace strcpy() with strncpy()\n"
        "2. Remove hardcoded credentials\n"
        "3. Enable NX protection\n");*/
    fprintf(f, "\n==================================================\n");
    printf("Successfully generated an automated report!\n");
}

static int check_file(char *filename, char *json_report)
{
    int fd = 0;
    struct stat sb = {0};
    char *buffer = NULL;
    binary_info_t bin = {NULL, 0, -1, false, -1, NULL, 0};
    FILE *json = NULL;
    FILE *report = NULL;

    printf("Analysing the file \"%s\"\n", filename);
    fd = open(filename, O_RDONLY);
    if (fd == -1)
        return (dprintf(2, "Error: File \"%s\" isn't valid or couldn't be opened.\n", filename), 1);
    if (fstat(fd, &sb) == -1)
        return (close(fd), 1);
    if ((buffer = calloc(sizeof(char), sb.st_size + 1)) == NULL)
        return (dprintf(2, ERROR_MALLOC), close(fd), 1);
    if (read(fd, buffer, sb.st_size) != sb.st_size)
        return (dprintf(2, "Error: Couldn't read in the \"%s\" file.\n", filename), free(buffer), buffer = NULL, close(fd), 1);
    bin.name = filename;
    if (analyze_binary(buffer, &bin))
        return 1;
    if (bin.total_risk <= 100)
        printf("Total risk for \"%s\": %s%d%%\e[0m\n", filename, total_risk_color(bin.total_risk), bin.total_risk);
    else
        printf("Total risk is above \e[0;101m100%%\e[0m, good job bro 👍\n");
    free(buffer);
    buffer = NULL;
    close(fd);
    json = fopen(json_report, "w");
    if (!json)
        return (dprintf(2, "Error: Couldn't write the JSON report.\n"), 1);
    write_json_report(json, &bin);
    fclose(json);
    report = fopen(remove_file_extension(json_report), "w");
    if (!report)
        return (dprintf(2, "Error: Couldn't write the report.\n"), 1);
    write_report(report, &bin);
    fclose(report);
    my_array_free(1, bin.vulnerabilities);
    return 0;
}

static void launch_ai_assistant(char **env, char *json_report)
{
    pid_t pid = fork();

    if (pid == 0) {
        char *argv[] = {"python3", "src/ai_explainer.py", json_report, NULL};
        execve("/usr/bin/python3", argv, env);
        perror("Execve");
        exit(1);
    }
    waitpid(pid, NULL, 0);
}

static void ask_for_report(bool *report)
{
    char *line = NULL;
    size_t len = 0;

    write(1, "Do you want to generate an AI report for every binary analyzed?: ", 66);
    getline(&line, &len, stdin);
    for (int i = 0; strcasecmp(line, "yes\n") != 0 && strcasecmp(line, "y\n") != 0 && strcasecmp(line, "no\n") != 0 && strcasecmp(line, "n\n") != 0; ++i) {
        printf("Please answer yes (y) or no (n).\n");
        write(1, "Do you want to generate an AI report for every binary analyzed?: ", 66);
        getline(&line, &len, stdin);
    }
    if (strcasecmp(line, "yes\n") == 0 || strcasecmp(line, "y\n") == 0)
        *report = true;
    free(line);
    line = NULL;
}

int binaryguard(int ac, char **av, char **env)
{
    int check = 0;
    bool ai_report = false;

    if (ac == 1)
        help();
    ask_for_report(&ai_report);
    for (int i = 1; av[i]; ++i) {
        char *json_report = calloc(sizeof(char), strlen(av[i]) + 15);
        snprintf(json_report, strlen(av[i]) + 15, "%s_report.json", get_file_name(av[i]));
        check = check_file(av[i], json_report);
        if (av[i + 1])
            printf("\n");
        if (ai_report && check == 0)
            launch_ai_assistant(env, json_report);
        free(json_report);
        json_report = NULL;
    }
    return 0;
}
