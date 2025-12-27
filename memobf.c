#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <stdint.h>

int main(){
    /*objdump of mov x0, #1337 payload 
    0000000000000000 <ltmp0>:
       0: d280a720      mov     x0, #0x539              ; =1337
       4: d65f03c0      ret

       ise reverse karenge ... will get shellcode bytes 
       kyu reverse? endianness (the order in which bytes are read)
    */
    // unsigned char shellcode[] = {
    //     0x20, 0xa7, 0x80, 0xd2,  // mov x0, #1337 
    //     0xc0, 0x03, 0x5f, 0xd6   // ret           
    // };

    //XOR key = 0xAA
    unsigned char encshellcode[] = {
        0x8a, 0x0d, 0x2a, 0x78,
        0x6a, 0xa9, 0xf5, 0x7c
    };

    size_t len = sizeof(encshellcode);

    uint8_t runtime_key = rand() & 0xFF;
    if(runtime_key == 0x00) runtime_key = 0x5A;

    void *memory = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(memory, encshellcode, len);

    struct timespec ts = {1, 0};
    nanosleep(&ts, NULL);

    for(size_t i=0; i<len; i++){
        ((uint8_t*)memory)[i] ^= 0xAA;
    }

    for(size_t i=0; i<len; i++){
        ((uint8_t*)memory)[i] ^= runtime_key;
    }

    for(size_t i=0; i<len; i++){
        ((uint8_t*)memory)[i] ^= runtime_key;
    }
    
    mprotect(memory, len, PROT_READ | PROT_EXEC);

    int (*fn)() = (int (*)())memory;
    int result = fn();

    mprotect(memory, len, PROT_READ | PROT_WRITE);
    memset(memory, 0x00, len);
    munmap(memory, len);
    printf("payload returned: %d\n", result);
    return 0;
}


// void memfrob(void *data, size_t len){
//     unsigned char *p = data;
//     for(size_t i=0; i<len; i++){
//         p[i]^=0x2A;
//     }
// }

// int main(){
//     char msg[] = "neocipher";
//     size_t msglen = strlen(msg);
//     printf("original text: %s\n", msg);
//     memfrob((void*)msg, msglen);
//     printf("1x obfuscation: %s\n", msg);
//     memfrob((void*)msg, msglen);
//     printf("2x obfuscation: %s\n", msg);
//     return 0;
// }