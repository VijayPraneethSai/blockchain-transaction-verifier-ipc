#include <stdlib.h>
#include <string.h>

#include "block_counts.h"
#include "hash.h"
#include "protocol.h"

#define BUCKETS 211

struct Entry {
    char key[WALLET_HASH_SIZE + 1];
    int times;
    struct Entry *next;
};

static struct Entry *table[BUCKETS];

void block_counts_add(const char *wallet) {
    unsigned int b = fnv1a(wallet) % BUCKETS;
    for (struct Entry *e = table[b]; e; e = e->next)
        if (strcmp(e->key, wallet) == 0) {
            e->times++;
            return;
        }
    struct Entry *e = malloc(sizeof *e);
    if (!e) exit(1);
    strcpy(e->key, wallet);
    e->times = 1;
    e->next = table[b];
    table[b] = e;
}

void block_counts_for_each(void (*fn)(const char *wallet, int times, void *ctx), void *ctx) {
    for (int b = 0; b < BUCKETS; b++)
        for (struct Entry *e = table[b]; e; e = e->next) fn(e->key, e->times, ctx);
}

void block_counts_clear(void) {
    for (int b = 0; b < BUCKETS; b++) {
        struct Entry *e = table[b];
        while (e) {
            struct Entry *next = e->next;
            free(e);
            e = next;
        }
        table[b] = NULL;
    }
}
