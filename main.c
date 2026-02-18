#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <unistd.h>

#define PERMS 0666
#define MAX_WALLETS_PER_BLOCK 100
#define WALLET_HASH_SIZE 16

struct Block {
 int wallet_count;
 char wallet_hashes[MAX_WALLETS_PER_BLOCK][WALLET_HASH_SIZE + 1];
};

struct RecvMessageBuffer {
 long mtype;
 int security_value;
 int decryption_key;
};

struct SendMessageBuffer {
 long mtype;
 long sum;
};

struct WalletData {
 long long sndExact[65];
 long long rcvExact[65];
 long long slfExact[65];
 long long sndTot[65];
 long long rcvTot[65];
 long long sflTot[65];
};

struct Wallet {
 char key[WALLET_HASH_SIZE + 1];
 struct WalletData wData;
 struct Wallet *next;
};

struct HNode {
 char key[WALLET_HASH_SIZE + 1];
 int nTimes;
 struct HNode *next;
};

struct HNode *hashTable[211]; // using hashTable bucket size = 211
struct Wallet *walletTable[10007]; // using walletTable size = 10007

// The hashing function based of FNV-1a
unsigned int hashingFunc(const char *key) {
 unsigned int hashVal = 2166136261u;
 for (int i = 0; key[i] != '\0'; i++) {
 hashVal ^= (unsigned char)key[i];
 hashVal *= 16777619u;
 }
 return hashVal;
}

// Inserting into the hash table
void hInsert(const char *key) {
 unsigned int ind = hashingFunc(key) % 211;
 struct HNode *currNode = hashTable[ind];
 while (currNode) {
 if (strcmp(currNode->key, key) == 0) {
 currNode->nTimes++;
 return;
 }
 currNode = currNode->next;
 }

 struct HNode *newNode = malloc(sizeof(struct HNode));
 if (!newNode) exit(1);
 strcpy(newNode->key, key);
 newNode->nTimes = 1;
 newNode->next = hashTable[ind];
 hashTable[ind] = newNode;
}

// Checking the presence, count in hash table
int hExists(const char *key) {
 unsigned int ind = hashingFunc(key) % 211; 
 struct HNode *curr = hashTable[ind];
 while (curr) {
 if (strcmp(curr->key, key) == 0) {
 return curr->nTimes;
 }
 curr = curr->next;
 }
 return 0;
}

// Clearing the hash table
void hClear() {
 for (int i = 0; i < 211; i++) {
 struct HNode *currNode = hashTable[i];
 while (currNode) {
 struct HNode *temp = currNode;
 currNode = currNode->next;
 free(temp);
 }
 hashTable[i] = NULL;
 }
}

// making the wallet entries
struct Wallet *makeWalletEntry(const char *key) {
 unsigned int ind = hashingFunc(key) % 10007; 
 struct Wallet *currNode = walletTable[ind];
 while (currNode) {
 if (strcmp(currNode->key, key) == 0) {
 return currNode;
 }
 currNode = currNode->next;
 }

 struct Wallet *newEn = malloc(sizeof(struct Wallet));
 if (!newEn) exit(1);
 strcpy(newEn->key, key);
 memset(&newEn->wData, 0, sizeof(struct WalletData));
 newEn->next = walletTable[ind];
 walletTable[ind] = newEn;
 return newEn;
}

// Finding the wallet entry
struct Wallet *findWalletEntry(const char *key) {
 unsigned int ind = hashingFunc(key) % 10007;
 struct Wallet *currWallet = walletTable[ind];
 while (currWallet) {
 if (strcmp(currWallet->key, key) == 0) {
 return currWallet;
 }
 currWallet = currWallet->next;
 }
 return NULL;
}

// Clearing the wallet table
void wClear() {
 for (int i = 0; i < 10007; i++) {
 struct Wallet *currWallet = walletTable[i];
 while (currWallet) {
 struct Wallet *temp = currWallet;
 currWallet = currWallet->next;
 free(temp);
 }
 walletTable[i] = NULL;
 }
}

int main(int argc, char *argv[]) {
 int test_no = atoi(argv[1]);

 char input_file[32] = "input_";
 char transaction_file[32] = "transactions_";
 char t[8];

 sprintf(t, "%d", test_no);
 strcat(input_file, t);
 strcat(input_file, ".txt");
 strcat(transaction_file, t);
 strcat(transaction_file, ".txt");

 int total_no_transactions;
 int block_size;
 key_t shmem_key;
 key_t mes_key;

 // Opening the input file
 FILE *ipfile = fopen(input_file, "r");
 if (!ipfile) {
 perror("Error in opening input file");
 return 1;
 }
 char line[128];

 // Reading the total_no_transactions
 if (fgets(line, sizeof(line), ipfile) == NULL) {
 perror("Error in reading total_no_transactions");
 return 1;
 }
 if (sscanf(line, "%d", &total_no_transactions) != 1) {
 fprintf(stderr, "Invalid format for total_no_transactions\n");
 return 1;
 }

 // Reading the block_size
 if (fgets(line, sizeof(line), ipfile) == NULL) {
 perror("Error in reading block_size");
 return 1;
 }
 if (sscanf(line, "%d", &block_size) != 1) {
 fprintf(stderr, "Invalid format for block_size\n");
 return 1;
 }

 // Reading the shmem_key
 if (fgets(line, sizeof(line), ipfile) == NULL) {
 perror("Error in reading shmem_key");
 return 1;
 }
 if (sscanf(line, "%d", &shmem_key) != 1) {
 fprintf(stderr, "Invalid format for shmem_key\n");
 return 1;
 }

 // Reading the mes_key
 if (fgets(line, sizeof(line), ipfile) == NULL) {
 perror("Error in reading mes_key");
 return 1;
 }
 if (sscanf(line, "%d", &mes_key) != 1) {
 fprintf(stderr, "Invalid format for mes_key\n");
 return 1;
 }

 fclose(ipfile);

 int shmemid;
 struct Block *shmemPtr;

 // Getting the shmemid
 shmemid = shmget(shmem_key, sizeof(struct Block) * block_size, PERMS);
 if (shmemid == -1) {
 perror("Error with shared memory");
 return 1;
 }

 // Attaching to the shared memory
 shmemPtr = (struct Block *)shmat(shmemid, NULL, 0);
 if (shmemPtr == (void *)-1) {
 perror("Error in shared memory attach");
 return 1;
 }

 // Getting the message queue ID
 int mesQid = msgget(mes_key, PERMS);
 if (mesQid == -1) {
 perror("Error in msgget");
 return 1;
 }

 // Allocating space for the transaction data
 char (*timestamps)[32] = malloc(sizeof(char[32]) * total_no_transactions);
 char (*hashes)[65] = malloc(sizeof(char[65]) * total_no_transactions);
 char (*senders)[WALLET_HASH_SIZE + 1] = malloc(sizeof(char[WALLET_HASH_SIZE + 1]) * total_no_transactions);
 char (*receivers)[WALLET_HASH_SIZE + 1] = malloc(sizeof(char[WALLET_HASH_SIZE + 1]) * total_no_transactions);
 long long *amounts = malloc(sizeof(long long) * total_no_transactions);
 int *leadingZeros = malloc(sizeof(int) * total_no_transactions);

 if (!timestamps || !hashes || !senders || !receivers || !amounts || !leadingZeros) {
 fprintf(stderr, "Memory allocation failed\n");
 return 1;
 }

 // Initializing the wallet table
 memset(walletTable, 0, sizeof(walletTable));

 // Opening the transaction file
 FILE *tr_file = fopen(transaction_file, "r");
 if (!tr_file) {
 perror("Error in opening transaction file");
 return 1;
 }

 int tr_index = 0;
 while (fgets(line, sizeof(line), tr_file) && tr_index < total_no_transactions) {
 if (sscanf(line, "%31s %64s %16s %16s %lld",
 timestamps[tr_index],
 hashes[tr_index],
 senders[tr_index],
 receivers[tr_index],
 &amounts[tr_index]) == 5) {

 // Computing the leading zeros for tr_index
 int leadZ = 0;
 while (leadZ < 64 && hashes[tr_index][leadZ] == '0') {
 leadZ++;
 }
 leadingZeros[tr_index] = leadZ;

 // Indexing the transaction
 struct Wallet *sEntry = makeWalletEntry(senders[tr_index]);
 sEntry->wData.sndExact[leadZ] += amounts[tr_index];

 struct Wallet *rEntry = makeWalletEntry(receivers[tr_index]);
 rEntry->wData.rcvExact[leadZ] += amounts[tr_index];

 if (strcmp(senders[tr_index], receivers[tr_index]) == 0) {
 sEntry->wData.slfExact[leadZ] += amounts[tr_index];
 }

 tr_index++;
 }
 }
 fclose(tr_file);

 // Computing suspicioud sums for each wallet
 for (int b = 0; b < 10007; b++) {
 for (struct Wallet *wEntry = walletTable[b]; wEntry; wEntry = wEntry->next) {
 // Sender
 wEntry->wData.sndTot[64] = wEntry->wData.sndExact[64];
 for (int k = 63; k >= 0; k--) {
 wEntry->wData.sndTot[k] = wEntry->wData.sndTot[k + 1] + wEntry->wData.sndExact[k];
 }
 // Receiver 
 wEntry->wData.rcvTot[64] = wEntry->wData.rcvExact[64];
 for (int k = 63; k >= 0; k--) {
 wEntry->wData.rcvTot[k] = wEntry->wData.rcvTot[k + 1] + wEntry->wData.rcvExact[k];
 }
 // Self
 wEntry->wData.sflTot[64] = wEntry->wData.slfExact[64];
 for (int k = 63; k >= 0; k--) {
 wEntry->wData.sflTot[k] = wEntry->wData.sflTot[k + 1] + wEntry->wData.slfExact[k];
 }
 }
 }

 // Processing each block
 for (int i = 0; i < block_size; i++) {
 struct RecvMessageBuffer rcv_buf;
 int rcvMsgSize = sizeof(rcv_buf) - sizeof(long);

 // Receiving the message
 if (msgrcv(mesQid, &rcv_buf, rcvMsgSize, 2, 0) == -1) {
 perror("Error in receiving message");
 return 1;
 }

 int sec_val = rcv_buf.security_value;
 int dec_key = rcv_buf.decryption_key;
 int wallet_count = shmemPtr[i].wallet_count;

 // Decrypting the wallets
 char decrypted_wallets[MAX_WALLETS_PER_BLOCK][WALLET_HASH_SIZE + 1];
 int shift = dec_key % WALLET_HASH_SIZE;

 for (int j = 0; j < wallet_count; j++) {
 char *encrypted = shmemPtr[i].wallet_hashes[j];
 for (int k = 0; k < WALLET_HASH_SIZE; k++) {
 decrypted_wallets[j][k] = encrypted[(k + WALLET_HASH_SIZE - shift) % WALLET_HASH_SIZE];
 }
 decrypted_wallets[j][WALLET_HASH_SIZE] = '\0';
 }

 // Inserting the decrypted wallets into the hash table for counts
 for (int l = 0; l < wallet_count; l++) {
 hInsert(decrypted_wallets[l]);
 }

 // Compute suspicious sum
 long long suspicious_sum = 0;
 if (sec_val <= 64) {
 for (int b = 0; b < 211; b++) {
 for (struct HNode *node = hashTable[b]; node; node = node->next) {
 struct Wallet *wEntry = findWalletEntry(node->key);
 if (wEntry) {
 long long S = wEntry->wData.sndTot[sec_val];
 long long R = wEntry->wData.rcvTot[sec_val];
 long long self = wEntry->wData.sflTot[sec_val];
 suspicious_sum += (long long)node->nTimes * (S + R -self);
 }
 }
 }
 }

 // Sending the result
 struct SendMessageBuffer snd_buf;
 snd_buf.mtype = 1;
 snd_buf.sum = (long)suspicious_sum;

 int sndMsgSize = sizeof(snd_buf) - sizeof(long);
 if (msgsnd(mesQid, &snd_buf, sndMsgSize, 0) == -1) {
 perror("Error in sending message");
 return 1;
 }

 // Clearin the hash table
 hClear();
 }

 //Clearin the allocated space
 free(timestamps);
 free(hashes);
 free(senders);
 free(receivers);
 free(amounts);
 free(leadingZeros);
 wClear();

 return 0;
}