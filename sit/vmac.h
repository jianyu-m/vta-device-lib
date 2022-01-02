
#pragma once

#include "aes_ni.h"

typedef uint8_t cacheline_t[64];
typedef uint8_t raw_counter_t[7];
typedef uint8_t raw_tag_t[7];

typedef struct {
    uint64_t c : 56;
    uint64_t pad : 8;
} data_t;

typedef struct {
    raw_counter_t counters[8];
    raw_tag_t tag;
    uint8_t pad;
} counter_t;

uint64_t vhash64(uint8_t *message) {
    data_t *c0 = (data_t*) (message + 0);
    data_t *c1 = (data_t*) (message + 7);
    data_t *c2 = (data_t*) (message + 14);
    data_t *c3 = (data_t*) (message + 21);
    data_t *c4 = (data_t*) (message + 28);
    data_t *c5 = (data_t*) (message + 35);
    data_t *c6 = (data_t*) (message + 42);
    data_t *c7 = (data_t*) (message + 49);
    data_t *c8 = (data_t*) (message + 56);
    return (c0->c) + (c1->c) + (c2->c) + (c3->c) + (c4->c) + (c5->c) + (c6->c) + (c7->c) + (c8->c);
}

// fake impl of vhash
uint64_t vhash56(uint8_t *message) {
    data_t *c0 = (data_t*) (message + 0);
    data_t *c1 = (data_t*) (message + 7);
    data_t *c2 = (data_t*) (message + 14);
    data_t *c3 = (data_t*) (message + 21);
    data_t *c4 = (data_t*) (message + 28);
    data_t *c5 = (data_t*) (message + 35);
    data_t *c6 = (data_t*) (message + 42);
    data_t *c7 = (data_t*) (message + 49);
    return (c0->c) + (c1->c) + (c2->c) + (c3->c) + (c4->c) + (c5->c) + (c6->c) + (c7->c);
}

inline void vmac56(__m128i *key_schedule, uint8_t *message, raw_tag_t tag, uint64_t counter) {
    // vmac computation
    // vmac(m, nonce) = Hash(M) + AES-128(Nonce)
    uint8_t nonce[16];
    uint8_t encrypted_nonce[16];
    memset(nonce, 0, 16);
    memcpy(nonce, &counter, sizeof(counter));
    aes128_enc(key_schedule, nonce, encrypted_nonce);
    uint64_t h = vhash56(message);
    uint64_t r = h + *(uint64_t*)(encrypted_nonce);
    memcpy(tag, &r, sizeof(raw_tag_t));
}

inline void vmac64(__m128i *key_schedule, uint8_t *message, raw_tag_t tag, uint64_t counter) {
    // vmac computation
    // vmac(m, nonce) = Hash(M) + AES-128(Nonce)
    uint8_t nonce[16];
    uint8_t encrypted_nonce[16];
    memset(nonce, 0, 16);
    memcpy(nonce, &counter, sizeof(counter));
    aes128_enc(key_schedule, nonce, encrypted_nonce);
    uint64_t h = vhash64(message);
    uint64_t r = h + *(uint64_t*)(encrypted_nonce);
    memcpy(tag, &r, sizeof(raw_tag_t));
}