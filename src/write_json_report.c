/*
** EPITECH PROJECT, 2026
** BinaryGuard
** File description:
** BinaryGuard file to write reports
*/

#include <stdio.h>
#include "binaryguard.h"

static char *canary_type(int canary_type)
{
    switch ((canary_type))
    {
    case CANARY_NONE:
        return "None, proceed with caution.";
    case CANARY_LIKELY_USED:
        return "Present, but not specifically used, still proceed with caution.";
    case CANARY_SUPPORT:
        return "Present and used.";
    default:
        return "Unspecified, proceed with caution.";
    }
}

void write_json_report(FILE *f, binary_info_t *bin)
{
    fprintf(f, "{\n");
    fprintf(f, "  \"binary\": \"%s\",\n", bin->name);
    fprintf(f, "  \"risk_score\": %d,\n", bin->total_risk);
    fprintf(f, "  \"protections\": {\n");
    fprintf(f, "    \"canary\": \"%s\",\n", canary_type(bin->canary_type));
    fprintf(f, "    \"pie\": %d,\n", bin->is_pie);
    fprintf(f, "    \"nx\": %d,\n", 0);
    fprintf(f, "    \"nb_potential_passwords\": %d\n", bin->nb_potential_passwds);
    fprintf(f, "  },\n");
    fprintf(f, "  \"vulnerabilities\": [\n");
    for (int i = 0; i < bin->vuln_count; i++)
        fprintf(f, "    \"%s\"%s\n", bin->vulnerabilities[i], (i + 1 < bin->vuln_count) ? "," : "");
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
}