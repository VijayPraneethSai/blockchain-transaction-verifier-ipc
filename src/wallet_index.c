#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "protocol.h"
#include "wallet_index.h"

#define BUCKETS 262139

/* totals[k] = amount of the transactions this wallet takes part in whose hash has k leading zeros
 * (cumulative, "at least k", once finalize has run). A transaction counts once for a wallet even if the wallet is
 * both sender and receiver, so the sender-minus-self-transfer bookkeeping is done when transactions are added. */
struct Wallet {
    char key[WALLET_HASH_SIZE + 1];
    long long totals[MAX_LEADING_ZEROS + 1];
    struct Wallet *next;
};

static struct Wallet *table[BUCKETS];

static struct Wallet *find(const char *key) {
    for (struct Wallet *w = table[fnv1a(key) % BUCKETS]; w; w = w->next)
        if (strcmp(w->key, key) == 0) return w;
    return NULL;
}

static struct Wallet *find_or_create(const char *key) {
    struct Wallet *w = find(key);
    if (w) return w;
    w = calloc(1, sizeof *w);
    if (!w) exit(1);
    strcpy(w->key, key);
    unsigned int b = fnv1a(key) % BUCKETS;
    w->next = table[b];
    table[b] = w;
    return w;
}

void wallet_index_add(const char *sender, const char *receiver, int leading_zeros, long long amount) {
    find_or_create(sender)->totals[leading_zeros] += amount;
    if (strcmp(sender, receiver) != 0) find_or_create(receiver)->totals[leading_zeros] += amount;
}

void wallet_index_finalize(void) {
    for (int b = 0; b < BUCKETS; b++)
        for (struct Wallet *w = table[b]; w; w = w->next)
            for (int k = MAX_LEADING_ZEROS - 1; k >= 0; k--) w->totals[k] += w->totals[k + 1];
}

int wallet_index_sum(const char *wallet, int min_zeros, long long *sum) {
    struct Wallet *w = find(wallet);
    if (!w) return 0;
    *sum = w->totals[min_zeros];
    return 1;
}

void wallet_index_clear(void) {
    for (int b = 0; b < BUCKETS; b++) {
        struct Wallet *w = table[b];
        while (w) {
            struct Wallet *next = w->next;
            free(w);
            w = next;
        }
        table[b] = NULL;
    }
}
