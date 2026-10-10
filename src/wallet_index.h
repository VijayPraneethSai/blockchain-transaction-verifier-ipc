#ifndef WALLET_INDEX_H
#define WALLET_INDEX_H

/*
 * For every wallet, the total amount of the transactions it takes part in, split by how many leading zeros
 * the transaction hash has. After wallet_index_finalize() the totals are cumulative, so "all transactions with
 * at least k leading zeros" is a single array read.
 */

void wallet_index_add(const char *sender, const char *receiver, int leading_zeros, long long amount);
void wallet_index_finalize(void);

/* Returns 1 and sets *sum if the wallet appears in any transaction. A transaction counts once even if the
 * wallet is both sender and receiver. min_zeros must be in 0..MAX_LEADING_ZEROS. */
int wallet_index_sum(const char *wallet, int min_zeros, long long *sum);

void wallet_index_clear(void);

#endif
