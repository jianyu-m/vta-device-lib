
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

#define MiB (1024 * 1024)
#define KiB (1024)

#define MEMORY_SIZE (128 * MiB)
#define TAG_SIZE (16 * MiB)
#define SIT_L0 (16 * MiB)
#define SIT_L1 (2 * MiB)
#define SIT_L2 (256 * KiB)
#define SIT_L3 (32 * KiB)
#define SIT_L4 (4 * KiB)

#define SIT_L0_CNT (SIT_L0 / 8)
#define SIT_L1_CNT (SIT_L1 / 8)
#define SIT_L2_CNT (SIT_L2 / 8)
#define SIT_L3_CNT (SIT_L3 / 8)
#define SIT_L4_CNT (SIT_L4 / 8)

#define SIT_L0_PRE (0)
#define SIT_L1_PRE (SIT_L0_PRE + SIT_L0_CNT)
#define SIT_L2_PRE (SIT_L1_PRE + SIT_L1_CNT)
#define SIT_L3_PRE (SIT_L2_PRE + SIT_L2_CNT)
#define SIT_L4_PRE (SIT_L3_PRE + SIT_L3_CNT)

typedef struct {
    union {
        struct {
            int main;
            int tag;
            int sit;
            int root;
        };
        int data[4];
    };

} memory_size_t;

typedef struct {
    union {
        struct {
            cacheline_t *memory;
            tag_t *tags;
            counter_t *sit;
            counter_t *root;
            uint8_t *raw_memory;
        };
        uint8_t* data[5];
    };

} memory_t;

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

inline void compare_tag(raw_tag_t a, raw_tag_t b) {
    int r = ((data_t *)a)->c == ((data_t *)b)->c;
    if (!r) {
        printf("tag is not the same!!\n");
    }
    // else {
    //     printf("tag is the same!!\n");
    // }
}

inline void copy_tag(raw_tag_t dst, raw_tag_t src) {
    memcpy(dst, src, sizeof(raw_tag_t));
}

#define DO_CHECK_(counter_ptr, hash_ptr, mtag, do_tag, hash_length, do_add)     \
    cnt_xp = cnt_x;                                                             \
    cnt_x = (cnt_xp / 8);                                                        \
    cnt_y = (cnt_xp % 8);                                                        \
    counter = (data_t *)(counter_ptr);                                          \
    if (do_add) counter->c += 1;                                                \
    vmac##hash_length(key_schedule, (uint8_t *)(hash_ptr), tag, counter->c);    \
    do_tag(mtag.tag, tag);

#define DO_CHECK_R(counter_ptr, mash_ptr, mtag, hash_length) DO_CHECK_(counter_ptr, mash_ptr, mtag, compare_tag, hash_length, 0)
#define DO_CHECK_W(counter_ptr, mash_ptr, mtag, hash_length) DO_CHECK_(counter_ptr, mash_ptr, mtag, copy_tag, hash_length, 1)

void read_cacheline(memory_t *memory, int index, uint8_t* plaintext, __m128i key_schedule[20]) {
    // aes128_enc(key_schedule, (uint8_t*) main_memory + index / 64, (uint8_t*) main_memory + 16);
    raw_tag_t tag;
    data_t *counter;
    int cnt_x, cnt_y, cnt_xp;

    aes128_dec_cacheline(key_schedule, (uint8_t *)(memory->raw_memory + index), plaintext);

    int cl_index = index / 64;
    cnt_x = cl_index;

    // compare the first level
    DO_CHECK_R(memory->sit[SIT_L0_PRE + cnt_x].counters[cnt_y], (memory->raw_memory + index), memory->tags[cl_index], 64);
    DO_CHECK_R(memory->sit[SIT_L1_PRE + cnt_x].counters[cnt_y], (memory->sit + cnt_xp + SIT_L0_PRE), memory->sit[cnt_xp + SIT_L0_PRE], 56);
    DO_CHECK_R(memory->sit[SIT_L2_PRE + cnt_x].counters[cnt_y], (memory->sit + cnt_xp + SIT_L1_PRE), memory->sit[cnt_xp + SIT_L1_PRE], 56);
    DO_CHECK_R(memory->sit[SIT_L3_PRE + cnt_x].counters[cnt_y], (memory->sit + cnt_xp + SIT_L2_PRE), memory->sit[cnt_xp + SIT_L2_PRE], 56);
    DO_CHECK_R(memory->root[cnt_x].counters[cnt_y], (memory->sit + cnt_xp + SIT_L3_PRE), memory->sit[cnt_xp + SIT_L3_PRE], 56);
}

void write_cacheline(memory_t *memory, int index, uint8_t* plaintext, __m128i key_schedule[20]) {
    raw_tag_t tag;
    data_t *counter;
    int cnt_x, cnt_y, cnt_xp;

    aes128_enc_cacheline(key_schedule, plaintext, (uint8_t *)(memory->raw_memory + index));

    int cl_index = index / 64;
    cnt_x = cl_index;

    // compare the first level
    DO_CHECK_W(memory->sit[SIT_L0_PRE + cnt_x].counters[cnt_y], (memory->raw_memory + index), memory->tags[cl_index], 64);
    DO_CHECK_W(memory->sit[SIT_L1_PRE + cnt_x].counters[cnt_y], (memory->sit + cnt_xp + SIT_L0_PRE), memory->sit[cnt_xp + SIT_L0_PRE], 56);
    DO_CHECK_W(memory->sit[SIT_L2_PRE + cnt_x].counters[cnt_y], (memory->sit + cnt_xp + SIT_L1_PRE), memory->sit[cnt_xp + SIT_L1_PRE], 56);
    DO_CHECK_W(memory->sit[SIT_L3_PRE + cnt_x].counters[cnt_y], (memory->sit + cnt_xp + SIT_L2_PRE), memory->sit[cnt_xp + SIT_L2_PRE], 56);
    DO_CHECK_W(memory->root[cnt_x].counters[cnt_y], (memory->sit + cnt_xp + SIT_L3_PRE), memory->sit[cnt_xp + SIT_L3_PRE], 56);
}

int main() {
    // we have 3 layers
    memory_size_t sizes = {128 * MiB, 16 * MiB, SIT_L0 + SIT_L1 + SIT_L2 + SIT_L3, SIT_L4};
    memory_t memory = {NULL, NULL, NULL, NULL};
    for (int i  = 0; i < 4;i++) {
        memory.data[i] = (uint8_t*) mmap(0, sizes.data[i], PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    memory.data[4] = memory.data[0];

    uint8_t enc_key[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    __m128i key_schedule[20];
    
    aes128_load_key(enc_key,key_schedule);
    
    // write_cacheline()
    uint8_t content[64];
    uint8_t content2[64];
    content[0] = 1;
    for (int i = 1;i < 4096 * 64;i++) {
        write_cacheline(&memory, 64 * i, content, key_schedule);
        read_cacheline(&memory, 64, content2, key_schedule);
    }
    printf("c %d\n", content2[0]);
}

// 9 -> (1 * 8  +1) -> (0 * 8 + 0)
// 0 -> (0 * 8 + 0) -> (0 * 8 + 0)
// 11111111 11111111