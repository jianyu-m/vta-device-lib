
#include <iostream>
#include <sodium.h>
#include <sys/mman.h>

// this simulate the SGX integrity tree (SIT)

void *main_memory;
void *tag_memory;
void *sit_memory;

#include "aes_ni.h"
#include "vmac.h"

#define MAIN_KB 4
#define TAG_KB 4
#define SIT_KB 4

int main() {
    int main_bytes = MAIN_KB * 1024;
    int tag_bytes = TAG_KB * 1024; 
    int sit_bytes = SIT_KB * 1024;
    main_memory = mmap(0, main_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    tag_memory = mmap(0, tag_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    sit_memory = mmap(0, sit_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    uint8_t enc_key[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    __m128i key_schedule[20];
    
    aes128_load_key(enc_key,key_schedule);
    aes128_enc(key_schedule, (uint8_t*) main_memory, (uint8_t*) main_memory + 16);
    aes128_dec(key_schedule,(uint8_t*) main_memory + 16,(uint8_t*) main_memory);

    vmac64(key_schedule, (uint8_t *)main_memory + 16, (uint8_t *)tag_memory, 0);

    std::cout << *(int*)(main_memory + 16) << "\n";
    std::cout << *(int*)main_memory <<  "\n";
    std::cout << *(int*)tag_memory <<  "\n";
}