#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void memfrob(void *data, size_t len){
    unsigned char *p = data;
    for (size_t i=0; i<len; i++){
        p[i]^=0x2A;
    }
}

int main(){
    char msg[] = "neocipher";
    size_t msglen = strlen(msg);
    printf("%s\n", msg);
    memfrob((void*)msg, msglen);
    printf("%s\n", msg);
    return 0;
}