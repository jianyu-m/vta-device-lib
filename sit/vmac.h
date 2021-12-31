
#pragma once

#include "aes_ni.h"

uint64_t vhash(uint8_t *message) {
    return *(uint64_t *)(message);
}

void vmac64(__m128i *key_schedule, uint8_t *message, uint8_t *tag, uint64_t counter) {
    // vmac computation
    // vmac(m, nonce) = Hash(M) + AES-128(Nonce)
    uint8_t nonce[16];
    uint8_t encrypted_nonce[16];
    memset(nonce, 0, 16);
    memcpy(nonce, &counter, sizeof(counter));
    aes128_enc(key_schedule, nonce, encrypted_nonce);
    uint64_t h = vhash(message);
    uint64_t r = h + *(uint64_t*)(encrypted_nonce);
    memcpy(tag, &r, sizeof(r));
}