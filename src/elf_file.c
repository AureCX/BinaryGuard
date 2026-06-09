/*
** EPITECH PROJECT, 2026
** BinaryGuard
** File description:
** BinaryGuard file that handles ELF binairies
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include "binaryguard.h"

static Elf64_Shdr *find_section(Elf64_Shdr *shdr, int shnum, const char *shstrtab, const char *target)
{
    for (int i = 0; i < shnum; i++) {
        const char *name = shstrtab + shdr[i].sh_name;
        if (strcmp(name, target) == 0)
            return &shdr[i];
    }
    return NULL;
}

static char **get_elf_functions(char *buffer, Elf64_Ehdr *header)
{
    Elf64_Shdr *shdr = (Elf64_Shdr *)(buffer + header->e_shoff);
    const char *shstrtab = buffer + shdr[header->e_shstrndx].sh_offset;
    Elf64_Shdr *symsec = NULL;
    Elf64_Shdr *strsec = NULL;
    char **functions_list = NULL;

    symsec = find_section(shdr, header->e_shnum, shstrtab, ".dynsym");
    strsec = find_section(shdr, header->e_shnum, shstrtab, ".dynstr");
    if (!symsec || !strsec) {
        symsec = find_section(shdr, header->e_shnum, shstrtab, ".symtab");
        strsec = find_section(shdr, header->e_shnum, shstrtab, ".strtab");
    }
    if (!symsec || !strsec)
        return NULL;
    Elf64_Sym *symtab = (Elf64_Sym *)(buffer + symsec->sh_offset);
    const char *dynstrtab = buffer + strsec->sh_offset;
    int count = symsec->sh_size / sizeof(Elf64_Sym);
    functions_list = calloc(sizeof(char *), count + 1);
    int idx = 0;
    for (int i = 0; i < count; i++) {
        const char *fname = dynstrtab + symtab[i].st_name;
        if (symtab[i].st_name == 0)
            continue;
        if (ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC) {
            functions_list[idx] = strdup(fname);
            ++idx;
        }
    }
    return functions_list;
}

static int has_stack_protector_relocation(char *buffer, Elf64_Ehdr *header)
{
    Elf64_Shdr *shdr = (Elf64_Shdr *)(buffer + header->e_shoff);
    const char *shstrtab = buffer + shdr[header->e_shstrndx].sh_offset;
    Elf64_Shdr *symsec = find_section(shdr, header->e_shnum, shstrtab, ".dynsym");
    Elf64_Shdr *strsec = find_section(shdr, header->e_shnum, shstrtab, ".dynstr");

    if (!symsec || !strsec) {
        symsec = find_section(shdr, header->e_shnum, shstrtab, ".symtab");
        strsec = find_section(shdr, header->e_shnum, shstrtab, ".strtab");
    }
    if (!symsec || !strsec)
        return -1;
    Elf64_Sym *symtab = (Elf64_Sym *)(buffer + symsec->sh_offset);
    const char *strtab = buffer + strsec->sh_offset;
    for (int i = 0; i < header->e_shnum; i++) {
        if (shdr[i].sh_type != SHT_RELA)
            continue;
        Elf64_Rela *rela = (Elf64_Rela *)(buffer + shdr[i].sh_offset);
        int count = shdr[i].sh_size / sizeof(Elf64_Rela);
        for (int j = 0; j < count; j++) {
            int sym_idx = ELF64_R_SYM(rela[j].r_info);
            if (sym_idx >= symsec->sh_size / sizeof(Elf64_Sym))
                continue;
            const char *name = strtab + symtab[sym_idx].st_name;
            if (!strcmp(name, "__stack_chk_fail") ||
                !strcmp(name, "__stack_chk_fail_local"))
                return 1;
        }
    }
    return 0;
}

static int has_stack_protector_support(char **functions)
{
    for (int i = 0; functions && functions[i]; ++i)
        if (strcmp(functions[i], "__stack_chk_fail") == 0) {
            return 1;
        }
    return 0;
}

static void check_for_stack_canary(char **functions, binary_info_t *bin, char *buffer, Elf64_Ehdr *header)
{
    if (!has_stack_protector_support(functions)) {
        bin->canary_type = CANARY_NONE;
        printf("No stack canary, ouch!\n");
    } else if (has_stack_protector_relocation(buffer, header)) {
        bin->canary_type = CANARY_LIKELY_USED;
        printf("Stack Canary is likely used!\n");
    } else {
        bin->canary_type = CANARY_SUPPORT;
        printf("Stack Canary is present, but not used, be careful.\n");
    }
}

#include <elf.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

char **get_strings_from_section(char *buffer, Elf64_Ehdr *header, const char *section_name)
{
    Elf64_Shdr *shdr = (Elf64_Shdr *)(buffer + header->e_shoff);
    const char *shstrtab = buffer + shdr[header->e_shstrndx].sh_offset;
    Elf64_Shdr *section = NULL;
    char **strings = NULL;
    int count = 0;
    int idx = 0;

    section = find_section(shdr, header->e_shnum, shstrtab, section_name);
    if (!section)
        return NULL;
    char *data = buffer + section->sh_offset;
    size_t size = section->sh_size;
    for (size_t i = 0; i < size;) {
        if (!isprint((unsigned char)data[i])) {
            i++;
            continue;
        }
        size_t start = i;
        while (i < size && isprint((unsigned char)data[i]))
            i++;
        if (i < size && data[i] == '\0' && (i - start) >= 4)
            count++;
        i++;
    }
    strings = calloc(sizeof(char *), count + 1);
    if (!strings)
        return NULL;
    for (size_t i = 0; i < size;) {
        if (!isprint((unsigned char)data[i])) {
            i++;
            continue;
        }
        size_t start = i;
        while (i < size && isprint((unsigned char)data[i]))
            i++;
        if (i < size && data[i] == '\0' && (i - start) >= 4) {
            strings[idx] = strndup(data + start, i - start);
            if (strings[idx])
                idx++;
        }
        i++;
    }
    strings[idx] = NULL;
    return strings;
}

static void check_for_weak_passwords(char *buffer, binary_info_t *bin, Elf64_Ehdr *header)
{
    FILE *pwd_file = fopen("resources/100-passwords.txt", "r");
    char **pwds = NULL;
    char **strings = get_strings_from_section(buffer, header, ".rodata");
    char *line = NULL;
    size_t len = 0;

    if (!pwd_file)
        return;
    for (int i = 0; getline(&line, &len, pwd_file) != -1; ++i) {
        pwds = realloc(pwds, sizeof(char *) * (i + 2));
        pwds[i] = strdup(line);
        pwds[i + 1] = NULL;
    }
    for (int i = 0; pwds[i]; ++i) {
        for (int j = 0; strings[j]; ++j)
            if (strncasecmp(pwds[i], strings[j], strlen(strings[j])) == 0) {
                printf("Potential password found\n");
                ++bin->nb_potential_passwds;
                bin->total_risk += 5;
            }
    }
    my_array_free(2, pwds, strings);
    free(line);
}

void elf_binary(char *buffer, binary_info_t *bin)
{
    Elf64_Ehdr *header = (Elf64_Ehdr *)buffer;
    char **functions = get_elf_functions(buffer, header);

    if (header->e_type == ET_DYN) {
        printf("Binary is PIE.\n");
        bin->is_pie = true;
    }
    else if (header->e_type == ET_EXEC)
        printf("Binary isn't PIE, be careful!\n");
    check_for_stack_canary(functions, bin, buffer, header);
    for (int i = 0; vuln_table[i].symbol; ++i)
        for (int j = 0; functions && functions[j]; ++j)
            if (strcmp(functions[j], vuln_table[i].symbol) == 0) {
                printf("Function \"%s\" detected: %s, %s and a severity of %d\n",
                    vuln_table[i].symbol, vuln_table[i].name, vuln_table[i].description, vuln_table[i].severity);
                bin->vulnerabilities = realloc(bin->vulnerabilities, sizeof(char *) * (bin->vuln_count + 2));
                bin->vulnerabilities[bin->vuln_count] = strdup(vuln_table[i].symbol);
                bin->vulnerabilities[bin->vuln_count + 1] = NULL;
                bin->vuln_count += 1;
                bin->total_risk += vuln_table[i].severity * ((bin->canary_type == CANARY_NONE && vuln_table[i].type == BUFFER_OVERFLOWS) ? 2 : 1);
                }
    check_for_weak_passwords(buffer, bin, header);
    my_array_free(1, functions);
}