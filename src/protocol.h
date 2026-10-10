#ifndef PROTOCOL_H
#define PROTOCOL_H

/* Layout of the shared memory segment and the two message types, as agreed with the process that fills them. */

#define PERMS 0666
#define MAX_WALLETS_PER_BLOCK 100
#define WALLET_HASH_SIZE 16
#define MAX_LEADING_ZEROS 64

struct Block {
    int wallet_count;
    char wallet_hashes[MAX_WALLETS_PER_BLOCK][WALLET_HASH_SIZE + 1];
};

/* request: mtype 2 */
struct RecvMessageBuffer {
    long mtype;
    int security_value;
    int decryption_key;
};

/* reply: mtype 1 */
struct SendMessageBuffer {
    long mtype;
    long sum;
};

#endif
