/*
 * Blockchain transaction verifier.
 *
 * Reads transactions from a file and indexes them per wallet, then answers one request per block: the
 * wallets of the block arrive encrypted in shared memory, the decryption key and a security value arrive on
 * a message queue, and the reply is the total amount of "suspicious" transactions touching those wallets.
 * A transaction is suspicious if its hash has at least `security value` leading zeros.
 *
 * usage: verifier <test_case_number>   (reads input_<n>.txt and transactions_<n>.txt)
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>

#include "block_counts.h"
#include "protocol.h"
#include "wallet_index.h"

struct Header {
    int total_transactions;
    int block_size;
    key_t shmem_key;
    key_t mes_key;
};

/* Four lines, one integer each: transaction count, number of blocks, shared memory key, queue key. */
static int read_header(const char *path, struct Header *h) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("Error in opening input file");
        return -1;
    }
    int values[4];
    const char *names[4] = {"total_no_transactions", "block_size", "shmem_key", "mes_key"};
    char line[128];
    for (int i = 0; i < 4; i++) {
        if (fgets(line, sizeof line, f) == NULL || sscanf(line, "%d", &values[i]) != 1) {
            fprintf(stderr, "Invalid or missing %s in %s\n", names[i], path);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    h->total_transactions = values[0];
    h->block_size = values[1];
    h->shmem_key = values[2];
    h->mes_key = values[3];
    if (h->total_transactions <= 0 || h->block_size <= 0) {
        fprintf(stderr, "total_no_transactions and block_size must be positive\n");
        return -1;
    }
    return 0;
}

/* Copies the next space-separated field of *p into out (at most max bytes). Returns 0 if there is none or it is too long. */
static int next_field(const char **p, char *out, size_t max) {
    const char *s = *p;
    while (*s == ' ' || *s == '\t') s++;
    size_t n = 0;
    while (s[n] && s[n] != ' ' && s[n] != '\t' && s[n] != '\n' && s[n] != '\r') n++;
    if (n == 0 || n > max) return 0;
    memcpy(out, s, n);
    out[n] = '\0';
    *p = s + n;
    return 1;
}

/* One transaction per line: timestamp hash sender receiver amount. Lines that do not parse are skipped.
 * The fields are split by hand: scanf with five conversions was most of the loading time (see the README). */
static int load_transactions(const char *path, int limit) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("Error in opening transaction file");
        return -1;
    }
    /* a valid line is at most about 155 bytes (31 + 64 + 16 + 16 + 20 digits + separators) */
    char line[256], timestamp[32], hash[65], sender[WALLET_HASH_SIZE + 1], receiver[WALLET_HASH_SIZE + 1], amount_text[24];
    int loaded = 0;
    while (loaded < limit && fgets(line, sizeof line, f)) {
        if (!strchr(line, '\n') && !feof(f)) {   /* longer than the buffer: it cannot be a valid line, drop the rest of it */
            int c;
            while ((c = fgetc(f)) != '\n' && c != EOF) {}
            continue;
        }
        const char *p = line;
        if (!next_field(&p, timestamp, 31) || !next_field(&p, hash, 64) || !next_field(&p, sender, WALLET_HASH_SIZE) ||
            !next_field(&p, receiver, WALLET_HASH_SIZE) || !next_field(&p, amount_text, 23))
            continue;
        char *end;
        long long amount = strtoll(amount_text, &end, 10);
        if (end == amount_text || *end != '\0') continue;
        int zeros = 0;
        while (zeros < MAX_LEADING_ZEROS && hash[zeros] == '0') zeros++;
        wallet_index_add(sender, receiver, zeros, amount);
        loaded++;
    }
    fclose(f);
    wallet_index_finalize();
    return 0;
}

/* The wallets were rotated by (key mod 16) positions; rotate them back. */
static void decrypt_wallets(const struct Block *blk, int key, char out[][WALLET_HASH_SIZE + 1]) {
    int shift = key % WALLET_HASH_SIZE;
    for (int j = 0; j < blk->wallet_count; j++) {
        for (int k = 0; k < WALLET_HASH_SIZE; k++)
            out[j][k] = blk->wallet_hashes[j][(k + WALLET_HASH_SIZE - shift) % WALLET_HASH_SIZE];
        out[j][WALLET_HASH_SIZE] = '\0';
    }
}

struct SumContext {
    int min_zeros;
    long long sum;
};

static void add_wallet_total(const char *wallet, int times, void *ctx) {
    struct SumContext *c = ctx;
    long long total;
    if (wallet_index_sum(wallet, c->min_zeros, &total)) c->sum += (long long)times * total;
}

static int serve_blocks(int queue_id, const struct Block *blocks, int block_count) {
    for (int i = 0; i < block_count; i++) {
        struct RecvMessageBuffer request;
        if (msgrcv(queue_id, &request, sizeof(request) - sizeof(long), 2, 0) == -1) {
            perror("Error in receiving message");
            return -1;
        }
        int wallet_count = blocks[i].wallet_count;
        /* shared memory is written by another process, so do not trust the count */
        if (wallet_count < 0 || wallet_count > MAX_WALLETS_PER_BLOCK) {
            fprintf(stderr, "block %d has an invalid wallet count: %d\n", i, wallet_count);
            return -1;
        }
        /* every hash has at least a negative number of leading zeros, so a negative value behaves like 0 */
        int min_zeros = request.security_value < 0 ? 0 : request.security_value;

        char wallets[MAX_WALLETS_PER_BLOCK][WALLET_HASH_SIZE + 1];
        decrypt_wallets(&blocks[i], request.decryption_key, wallets);
        for (int j = 0; j < wallet_count; j++) block_counts_add(wallets[j]);

        struct SumContext ctx = {min_zeros, 0};
        if (min_zeros <= MAX_LEADING_ZEROS) block_counts_for_each(add_wallet_total, &ctx);

        struct SendMessageBuffer reply = {1, (long)ctx.sum};
        if (msgsnd(queue_id, &reply, sizeof(reply) - sizeof(long), 0) == -1) {
            perror("Error in sending message");
            return -1;
        }
        block_counts_clear();
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <test_case_number>\n", argv[0]);
        return 2;
    }
    char *end;
    long test_no = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || test_no < 0 || test_no > 999999) {
        fprintf(stderr, "invalid test case number: %s\n", argv[1]);
        return 2;
    }
    char input_file[64], transaction_file[64];
    snprintf(input_file, sizeof input_file, "input_%ld.txt", test_no);
    snprintf(transaction_file, sizeof transaction_file, "transactions_%ld.txt", test_no);

    struct Header h;
    if (read_header(input_file, &h) != 0) return 1;

    int shmem_id = shmget(h.shmem_key, sizeof(struct Block) * h.block_size, PERMS);
    if (shmem_id == -1) {
        perror("Error with shared memory");
        return 1;
    }
    struct Block *blocks = shmat(shmem_id, NULL, 0);
    if (blocks == (void *)-1) {
        perror("Error in shared memory attach");
        return 1;
    }
    int queue_id = msgget(h.mes_key, PERMS);
    if (queue_id == -1) {
        perror("Error in msgget");
        return 1;
    }

    if (load_transactions(transaction_file, h.total_transactions) != 0) return 1;
    int status = serve_blocks(queue_id, blocks, h.block_size);
    wallet_index_clear();
    return status == 0 ? 0 : 1;
}
