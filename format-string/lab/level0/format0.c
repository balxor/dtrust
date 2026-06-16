#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln() {
    char buf[256];
    int secret = 0xdeadbeef;
    int cookie = 0xcafebabe;

    printf("Format String Lab - Level 0: Stack Leak\n");
    printf("========================================\n");
    printf("Goal: Find where your input appears on the stack.\n\n");

    printf("Enter input: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    printf("You entered: ");
    printf(buf);
    printf("\n");

    printf("\n[DEBUG] secret  = 0x%08x (should be 0xdeadbeef)\n", secret);
    printf("[DEBUG] cookie  = 0x%08x (should be 0xcafebabe)\n", cookie);
    printf("[DEBUG] buf addr = %p\n", buf);
}

int main() {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
