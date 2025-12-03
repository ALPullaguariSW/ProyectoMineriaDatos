#include <stdio.h>
#include <string.h>

void process_input() {
    char buffer[10];
    // VULNERABLE: gets() does not check buffer size
    gets(buffer);
}
