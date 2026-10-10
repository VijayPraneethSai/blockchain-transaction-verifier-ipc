/*
 * Test driver for the verifier. It plays the role of the course harness: it writes the input files,
 * creates the shared memory segment and the message queue, starts the verifier, sends one request per
 * block and checks every reply against an independent calculation.
 *
 *   driver <verifier> <seed> <transactions> <blocks> <wallets> [--brute] [--negative-sec] [--bad-count]
 *
 * --bad-count corrupts the wallet count of block 0 and expects the verifier to refuse it: exit status 1, no reply.
 *
 * The wire format below is the contract with the verifier (it is deliberately not shared with its source).
 * Exit status 0 = every block matched.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WALLET_LEN 16
#define MAX_WALLETS 100

struct Block {
    int wallet_count;
    char wallet_hashes[MAX_WALLETS][WALLET_LEN + 1];
};
struct Request { long mtype; int security_value; int decryption_key; };   /* mtype 2 */
struct Reply   { long mtype; long sum; };                                  /* mtype 1 */

static uint64_t rng_state;
static uint64_t rnd(void) {                       /* xorshift64: reproducible from the seed */
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
    return rng_state;
}
static int rnd_int(int lo, int hi) { return lo + (int)(rnd() % (uint64_t)(hi - lo + 1)); }

static int shm_id = -1, mq_id = -1;
static char workdir[64] = "";
static pid_t child = 0;

static void cleanup(void) {
    if (child > 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); child = 0; }
    if (shm_id >= 0) shmctl(shm_id, IPC_RMID, NULL);
    if (mq_id >= 0) msgctl(mq_id, IPC_RMID, NULL);
    if (workdir[0]) {
        char p[128];
        snprintf(p, sizeof p, "%s/input_1.txt", workdir); unlink(p);
        snprintf(p, sizeof p, "%s/transactions_1.txt", workdir); unlink(p);
        rmdir(workdir);
    }
}
static void die(const char *msg) { perror(msg); cleanup(); exit(2); }
static void on_signal(int s) { (void)s; cleanup(); _exit(2); }

static double now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

struct Tx { int sender, receiver, zeros; long long amount; };

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: %s <verifier> <seed> <transactions> <blocks> <wallets> [--brute] [--negative-sec] [--bad-count]\n", argv[0]); return 2; }
    char verifier[4096];
    if (!realpath(argv[1], verifier)) { perror("verifier path"); return 2; }   /* the child changes directory */
    rng_state = strtoull(argv[2], NULL, 10) * 2654435761u + 88172645463325252ull;
    int T = atoi(argv[3]), B = atoi(argv[4]), W = atoi(argv[5]);
    int brute = 0, negative_sec = 0, bad_count = 0;
    for (int i = 6; i < argc; i++) {
        if (!strcmp(argv[i], "--brute")) brute = 1;
        else if (!strcmp(argv[i], "--negative-sec")) negative_sec = 1;
        else if (!strcmp(argv[i], "--bad-count")) bad_count = 1;
    }
    if (T < 1 || B < 1 || W < 1) { fprintf(stderr, "transactions, blocks and wallets must be >= 1\n"); return 2; }
    for (int i = 0; i < 10; i++) rnd();

    signal(SIGINT, on_signal); signal(SIGTERM, on_signal);

    /* wallet ids are 16 hex characters */
    char (*wallet)[WALLET_LEN + 1] = malloc((size_t)W * (WALLET_LEN + 1));
    for (int i = 0; i < W; i++) {
        for (int k = 0; k < WALLET_LEN; k++) wallet[i][k] = "0123456789abcdef"[rnd() & 15];
        wallet[i][WALLET_LEN] = '\0';
    }

    /* transactions: the leading-zero count of the hash is what the security value is compared with.
       Mostly small counts, with some 0 and some very long runs so the 64-zero boundary is exercised. */
    struct Tx *tx = malloc((size_t)T * sizeof *tx);
    char (*hash)[65] = malloc((size_t)T * 65);
    for (int i = 0; i < T; i++) {
        int r = rnd_int(0, 99), z;
        if (r < 55) z = rnd_int(0, 6); else if (r < 90) z = rnd_int(7, 20); else if (r < 97) z = rnd_int(21, 63); else z = 64;
        for (int k = 0; k < 64; k++) hash[i][k] = k < z ? '0' : "123456789abcdef"[rnd() % 15];
        hash[i][64] = '\0';
        tx[i].zeros = z;
        tx[i].sender = rnd_int(0, W - 1);
        tx[i].receiver = rnd_int(0, 99) < 5 ? tx[i].sender : rnd_int(0, W - 1);   /* about 5% self transfers */
        tx[i].amount = rnd_int(1, 1000000);
    }

    /* blocks: 0..100 wallets each (so empty and full blocks both occur), duplicates allowed */
    struct Block *blocks = calloc((size_t)B, sizeof *blocks);
    int (*members)[MAX_WALLETS] = malloc((size_t)B * sizeof *members);
    struct Request *req = malloc((size_t)B * sizeof *req);
    for (int b = 0; b < B; b++) {
        int c = rnd_int(0, 9) == 0 ? (rnd_int(0, 1) ? 0 : MAX_WALLETS) : rnd_int(1, MAX_WALLETS);
        blocks[b].wallet_count = c;
        req[b].mtype = 2;
        req[b].decryption_key = rnd_int(0, 1000000);
        req[b].security_value = negative_sec ? rnd_int(-5, 70) : rnd_int(0, 70);   /* 65..70: nothing can match */
        int shift = req[b].decryption_key % WALLET_LEN;
        for (int j = 0; j < c; j++) {
            members[b][j] = rnd_int(0, W - 1);
            /* the verifier undoes a rotation: plain[k] = enc[(k - shift) mod 16], so enc[m] = plain[(m + shift) mod 16] */
            for (int m = 0; m < WALLET_LEN; m++)
                blocks[b].wallet_hashes[j][m] = wallet[members[b][j]][(m + shift) % WALLET_LEN];
            blocks[b].wallet_hashes[j][WALLET_LEN] = '\0';
        }
    }

    /* Expected answers, computed a different way from the verifier: each wallet keeps the list of
       transactions it takes part in (once, even for a self transfer), and a query walks that list. */
    int *start = calloc((size_t)W + 1, sizeof *start), *fill = calloc((size_t)W, sizeof *fill);
    for (int i = 0; i < T; i++) { start[tx[i].sender + 1]++; if (tx[i].receiver != tx[i].sender) start[tx[i].receiver + 1]++; }
    for (int w = 0; w < W; w++) start[w + 1] += start[w];
    int *list = malloc((size_t)start[W] * sizeof *list + 1);
    for (int i = 0; i < T; i++) {
        list[start[tx[i].sender] + fill[tx[i].sender]++] = i;
        if (tx[i].receiver != tx[i].sender) list[start[tx[i].receiver] + fill[tx[i].receiver]++] = i;
    }
    long *expected = calloc((size_t)B, sizeof *expected);
    for (int b = 0; b < B; b++) {
        long long sum = 0;
        for (int j = 0; j < blocks[b].wallet_count; j++) {
            int w = members[b][j];
            if (brute) {              /* slowest possible reading of the definition, for small cases */
                for (int i = 0; i < T; i++)
                    if ((tx[i].sender == w || tx[i].receiver == w) && tx[i].zeros >= req[b].security_value) sum += tx[i].amount;
            } else {
                for (int e = start[w]; e < start[w + 1]; e++)
                    if (tx[list[e]].zeros >= req[b].security_value) sum += tx[list[e]].amount;
            }
        }
        expected[b] = (long)sum;
    }

    if (bad_count) blocks[0].wallet_count = (rnd() & 1) ? MAX_WALLETS + 1 : -1;   /* after the expected values are computed */

    /* files for the verifier */
    snprintf(workdir, sizeof workdir, "/tmp/bcv_%d", (int)getpid());
    if (mkdir(workdir, 0700) != 0) die("mkdir");
    key_t shm_key = 0x4b000000 + (getpid() & 0xffff), mq_key = 0x4c000000 + (getpid() & 0xffff);
    char path[128];
    snprintf(path, sizeof path, "%s/input_1.txt", workdir);
    FILE *f = fopen(path, "w"); if (!f) die("input file");
    fprintf(f, "%d\n%d\n%d\n%d\n", T, B, (int)shm_key, (int)mq_key);
    fclose(f);
    snprintf(path, sizeof path, "%s/transactions_1.txt", workdir);
    f = fopen(path, "w"); if (!f) die("transactions file");
    for (int i = 0; i < T; i++)
        fprintf(f, "2024-01-01T00:00:%02d %s %s %s %lld\n", i % 60, hash[i], wallet[tx[i].sender], wallet[tx[i].receiver], tx[i].amount);
    fclose(f);

    /* shared memory and queue */
    shm_id = shmget(shm_key, sizeof(struct Block) * (size_t)B, IPC_CREAT | IPC_EXCL | 0666);
    if (shm_id < 0) die("shmget");
    void *mem = shmat(shm_id, NULL, 0);
    if (mem == (void *)-1) die("shmat");
    memcpy(mem, blocks, sizeof(struct Block) * (size_t)B);
    mq_id = msgget(mq_key, IPC_CREAT | IPC_EXCL | 0666);
    if (mq_id < 0) die("msgget");

    double t0 = now_ms();
    child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        if (chdir(workdir) != 0) _exit(127);
        execl(verifier, verifier, "1", (char *)NULL);
        _exit(127);
    }

    /* one request, one reply, in block order; give up if the verifier exits or stalls */
    int bad = 0;
    for (int b = 0; b < B && !bad; b++) {
        size_t rsz = sizeof(struct Request) - sizeof(long);
        while (msgsnd(mq_id, &req[b], rsz, IPC_NOWAIT) == -1) {
            if (errno != EAGAIN && errno != EINTR) die("msgsnd");
            usleep(200);
        }
        struct Reply rep;
        double wait_start = now_ms();
        for (;;) {
            ssize_t n = msgrcv(mq_id, &rep, sizeof rep - sizeof(long), 1, IPC_NOWAIT);
            if (n >= 0) break;
            if (errno != ENOMSG && errno != EINTR) die("msgrcv");
            int st;
            if (waitpid(child, &st, WNOHANG) == child) {
                child = 0;
                if (bad_count && b == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 1) {
                    printf("ok seed=%s: corrupt wallet count was refused (exit status 1)\n", argv[2]);
                    cleanup(); return 0;
                }
                fprintf(stderr, "FAIL: verifier exited early (status %d) before block %d\n", st, b);
                cleanup();
                return 1;
            }
            if (now_ms() - wait_start > 120000) { fprintf(stderr, "FAIL: no reply for block %d within 120 s\n", b); cleanup(); return 1; }
            usleep(100);
        }
        if (rep.sum != expected[b]) {
            fprintf(stderr, "FAIL: block %d (wallets=%d, security=%d): verifier=%ld expected=%ld\n",
                    b, blocks[b].wallet_count, req[b].security_value, rep.sum, expected[b]);
            bad = 1;
        }
    }
    double total = now_ms() - t0;
    int st = 0;
    if (!bad) {
        waitpid(child, &st, 0); child = 0;
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { fprintf(stderr, "FAIL: verifier exit status %d\n", st); bad = 1; }
    }
    cleanup();
    if (!bad && bad_count) { fprintf(stderr, "FAIL: the corrupt wallet count of block 0 was not refused\n"); return 1; }
    if (bad) return 1;
    printf("ok seed=%s transactions=%d blocks=%d wallets=%d total_ms=%.1f\n", argv[2], T, B, W, total);
    return 0;
}
