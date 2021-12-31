
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

#define CACHE_SIZE 64

typedef struct {
    union {
        struct {
            int main;
            int tag;
            int sit;
        };
        int data[3];
    };

} memory_size_t;

typedef struct {
    union {
        struct {
            cacheline_t *memory;
            raw_tag_t *tags;
            counter_t *sit;
            uint8_t *raw_memory;
        };
        uint8_t* data[4];
    };

} memory_t;

data_t root_cnt = {0, 0};

void aes128_dec_cacheline(__m128i key_schedule[20], uint8_t *cipher, uint8_t *plaintext) {
    aes128_dec(key_schedule, (uint8_t *)cipher + 0 , (uint8_t *)plaintext + 0 );
    aes128_dec(key_schedule, (uint8_t *)cipher + 16, (uint8_t *)plaintext + 16);
    aes128_dec(key_schedule, (uint8_t *)cipher + 32, (uint8_t *)plaintext + 32);
    aes128_dec(key_schedule, (uint8_t *)cipher + 48, (uint8_t *)plaintext + 48);
}

void aes128_enc_cacheline(__m128i key_schedule[20], uint8_t *plaintext, uint8_t *cipher) {
    aes128_enc(key_schedule, (uint8_t *)plaintext + 0 , (uint8_t *)cipher + 0 );
    aes128_enc(key_schedule, (uint8_t *)plaintext + 16, (uint8_t *)cipher + 16);
    aes128_enc(key_schedule, (uint8_t *)plaintext + 32, (uint8_t *)cipher + 32);
    aes128_enc(key_schedule, (uint8_t *)plaintext + 48, (uint8_t *)cipher + 48);
}

inline int compare_tag(raw_tag_t a, raw_tag_t b) {
    return ((data_t *)a)->c == ((data_t *)b)->c;
}

inline void copy_tag(raw_tag_t dst, raw_tag_t src) {
    memcpy(dst, src, sizeof(raw_tag_t));
}

void read_cacheline(memory_t *memory, int index, uint8_t* plaintext, __m128i key_schedule[20]) {
    // aes128_enc(key_schedule, (uint8_t*) main_memory + index / 64, (uint8_t*) main_memory + 16);
    raw_tag_t tag;
    data_t *counter;

    aes128_dec_cacheline(key_schedule, (uint8_t *)(memory->raw_memory + index), plaintext);

    int cl_index = index / 64;
    int cnt_div = cl_index / 8;
    int cnt_mod = cl_index % 8;

    // compare the first level
    counter = (data_t *)(memory->sit[cnt_div].counters[cnt_mod]);
    vmac64(key_schedule, (uint8_t *)(memory->raw_memory + index), tag, counter->c);
    compare_tag(memory->tags[cl_index], tag);
    // memcmp(tag, memory[1] + cl_index * 8, 7);

    // compare the second level
    raw_tag_t tag2;
    vmac56(key_schedule, (uint8_t*)(&memory->sit[cnt_div]), tag2, root_cnt.c);
    compare_tag(memory->sit[cnt_div].tag, tag2);
}

void write_cacheline(memory_t *memory, int index, uint8_t* plaintext, __m128i key_schedule[20]) {
    // aes128_enc(key_schedule, (uint8_t*) main_memory + index / 64, (uint8_t*) main_memory + 16);
    uint8_t tag[16];
    data_t *counter;

    aes128_enc_cacheline(key_schedule, plaintext, (uint8_t *)(memory->raw_memory + index));

    int cl_index = index / 64;
    int cnt_div = cl_index / 8;
    int cnt_mod = cl_index % 8;

    // compare the first level
    counter = (data_t *)(memory->sit[cnt_div].counters[cnt_mod]);
    vmac64(key_schedule, (uint8_t *)(memory->raw_memory + index), tag, counter->c);
    copy_tag(memory->tags[cl_index], tag);

    // compare the second level
    raw_tag_t tag2;
    root_cnt.c += 1;
    vmac56(key_schedule, (uint8_t*)(&memory->sit[cnt_div]), tag2, root_cnt.c);
    copy_tag(memory->sit[cnt_div].tag, tag2);
}

int main() {
    memory_size_t sizes = {4096, 4096, 4096};
    memory_t memory = {NULL, NULL, NULL};
    for (int i  = 0; i < 3;i++) {
        memory.data[i] = (uint8_t*) mmap(0, sizes.data[i], PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    memory.data[3] = memory.data[0];

    uint8_t enc_key[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    __m128i key_schedule[20];
    
    aes128_load_key(enc_key,key_schedule);
    
    // write_cacheline()
    uint8_t content[64];
    uint8_t content2[64];
    content[0] = 1;
    write_cacheline(&memory, 0, content, key_schedule);
    read_cacheline(&memory, 0, content2, key_schedule);
    printf("c %d\n", content2[0]);
}