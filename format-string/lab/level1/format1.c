/*
 * Author: Kenshin Himura
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char secret[64] = "FLAG{format_string_arbitrary_read_pwned!}";

void vuln() {
    char buf[256];

    printf("Format String Lab - Level 1: Arbitrary Read\n");
    printf("============================================\n");
    printf("Goal: Read the secret string using %%s.\n\n");
    printf("secret @ %p\n", secret);

    printf("Enter input: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    printf("You entered: ");
    printf(buf);
    printf("\n");
}

int main() {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
