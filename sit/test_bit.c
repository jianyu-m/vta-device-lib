
#include <stdio.h>
#include <stdint.h>

typedef struct {
    uint64_t c : 56;
    // uint64_t pad : 8;
} counter_t;

int main() {
    
    char buf[8];
    uint64_t *c = (uint64_t*)buf;
    memset(buf, 0, 8);
    // memset(buf, 255, 0);
    counter_t *cc = (counter_t *)buf;
    // cc->pad = 255;
    printf("value %lu %lu %d\n", *c, cc->c, sizeof(counter_t));
}