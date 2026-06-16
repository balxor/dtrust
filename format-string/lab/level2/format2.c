#include <stdio.h>
 * Author: Kenshin Himura
#include <stdlib.h>
#include <string.h>

int target = 0;

void win() {
    printf("\n[+] target successfully modified!\n");
    printf("[+] Exploit successful! Spawning shell...\n");
    system("/bin/sh");
}

void vuln() {
    char buf[256];

    printf("Format String Lab - Level 2: Basic Write (%%n)\n");
    printf("==============================================\n");
    printf("Goal: Modify 'target' to non-zero using %%n.\n\n");
    printf("target @ %p (current value: %d)\n", &target, target);

    printf("Enter input: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    printf("You entered: ");
    printf(buf);
    printf("\n");

    if (target != 0) {
        win();
    } else {
        printf("target = %d. Still zero. Try again.\n", target);
    }
}

int main() {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
