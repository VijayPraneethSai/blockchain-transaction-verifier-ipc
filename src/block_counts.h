#ifndef BLOCK_COUNTS_H
#define BLOCK_COUNTS_H

/* How many times each wallet appears in the block being processed. */

void block_counts_add(const char *wallet);
void block_counts_for_each(void (*fn)(const char *wallet, int times, void *ctx), void *ctx);
void block_counts_clear(void);

#endif
