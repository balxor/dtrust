#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    printf("\n============================================\n");
    printf("  [!!!] CONTAINER/VM ESCAPED - ROOT SHELL\n");
    printf("============================================\n\n");
    system("/bin/sh");
}

void vuln() {
    char buf[256];

    printf("Format String Lab - Level 4: Full Chain (GOT Overwrite)\n");
    printf("========================================================\n");
    printf("Goal: Overwrite exit@GOT with win() to get shell.\n");
    printf("Hint: This is a ONE-SHOT exploit in a single printf call.\n\n");
    printf("win()   @ %p\n", win);
    printf("exit()  @ %p (PLT)\n", exit);

    printf("Enter payload: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    printf("echo: ");
    printf(buf);
    printf("\n");

    printf("Calling exit(0)...\n");
    exit(0);
}

int main() {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
