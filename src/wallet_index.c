#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "protocol.h"
#include "wallet_index.h"

#define BUCKETS 10007

struct Wallet {
    char key[WALLET_HASH_SIZE + 1];
    long long snd_exact[MAX_LEADING_ZEROS + 1];   /* as sender, by exact leading-zero count */
    long long rcv_exact[MAX_LEADING_ZEROS + 1];
    long long self_exact[MAX_LEADING_ZEROS + 1];  /* sender == receiver */
    long long snd_tot[MAX_LEADING_ZEROS + 1];     /* at least k leading zeros, filled by finalize */
    long long rcv_tot[MAX_LEADING_ZEROS + 1];
    long long self_tot[MAX_LEADING_ZEROS + 1];
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
    find_or_create(sender)->snd_exact[leading_zeros] += amount;
    find_or_create(receiver)->rcv_exact[leading_zeros] += amount;
    if (strcmp(sender, receiver) == 0) find_or_create(sender)->self_exact[leading_zeros] += amount;
}

static void suffix_sums(const long long *exact, long long *total) {
    total[MAX_LEADING_ZEROS] = exact[MAX_LEADING_ZEROS];
    for (int k = MAX_LEADING_ZEROS - 1; k >= 0; k--) total[k] = total[k + 1] + exact[k];
}

void wallet_index_finalize(void) {
    for (int b = 0; b < BUCKETS; b++)
        for (struct Wallet *w = table[b]; w; w = w->next) {
            suffix_sums(w->snd_exact, w->snd_tot);
            suffix_sums(w->rcv_exact, w->rcv_tot);
            suffix_sums(w->self_exact, w->self_tot);
        }
}

int wallet_index_sum(const char *wallet, int min_zeros, long long *sum) {
    struct Wallet *w = find(wallet);
    if (!w) return 0;
    /* a self transfer is in both the sender and the receiver totals, so subtract it once */
    *sum = w->snd_tot[min_zeros] + w->rcv_tot[min_zeros] - w->self_tot[min_zeros];
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
