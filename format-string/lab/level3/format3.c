#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int target = 0x11111111;

void win() {
    printf("\n[+] target == 0xdeadbeef!\n");
    printf("[+] Exploit successful! Spawning shell...\n");
    system("/bin/sh");
}

void vuln() {
    char buf[256];

    printf("Format String Lab - Level 3: Precise Write (%%hn)\n");
    printf("=================================================\n");
    printf("Goal: Set target to EXACTLY 0xdeadbeef using %%hn.\n\n");
    printf("target @ %p (current: 0x%08x, target: 0xdeadbeef)\n", &target, target);

    printf("Enter input: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    printf("You entered: ");
    printf(buf);
    printf("\n");

    if (target == 0xdeadbeef) {
        win();
    } else {
        printf("target = 0x%08x. Expected 0xdeadbeef. Try again.\n", target);
    }
}

int main() {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
