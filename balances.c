#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ec.h>

#include "block.h"
#include "common.h"
#include "transaction.h"

/* Usage: ./balances *.blk
 * Reads in a list of block files and outputs a table of public key hashes and
 * their balance in the longest chain of blocks. In case there is more than one
 * chain of the longest length, chooses one arbitrarily. */

/* If a block has height 0, it must have this specific hash. */
const hash_output GENESIS_BLOCK_HASH = {
	0x00, 0x00, 0x00, 0x0e, 0x5a, 0xc9, 0x8c, 0x78, 0x98, 0x00, 0x70, 0x2a, 0xd2, 0xa6, 0xf3, 0xca,
	0x51, 0x0d, 0x40, 0x9d, 0x6c, 0xca, 0x89, 0x2e, 0xd1, 0xc7, 0x51, 0x98, 0xe0, 0x4b, 0xde, 0xec,
};

struct blockchain_node {
	struct blockchain_node *parent;
	struct block b;
	bool is_valid;
};

/* A simple linked list to keep track of account balances. */
struct balance {
	struct ecdsa_pubkey pubkey;
	int balance;
	struct balance *next;
};

/* Add or subtract an amount from a linked list of balances. Call it like this:
 *   struct balance *balances = NULL;
 *
 *   // reward_tx increment.
 *   balances = balance_add(balances, &b.reward_tx.dest_pubkey, 1);
 *
 *   // normal_tx increment and decrement.
 *   balances = balance_add(balances, &b.normal_tx.dest_pubkey, 1);
 *   balances = balance_add(balances, &prev_transaction.dest_pubkey, -1);
 */
static struct balance *balance_add(struct balance *balances,
	struct ecdsa_pubkey *pubkey, int amount)
{
	struct balance *p;

	for (p = balances; p != NULL; p = p->next) {
		if ((byte32_cmp(p->pubkey.x, pubkey->x) == 0)
			&& (byte32_cmp(p->pubkey.y, pubkey->y) == 0)) {
			p->balance += amount;
			return balances;
		}
	}

	/* Not found; create a new list element. */
	p = malloc(sizeof(struct balance));
	if (p == NULL)
		return NULL;
	p->pubkey = *pubkey;
	p->balance = amount;
	p->next = balances;

	return p;
}

/*Function to test blockchain_node_is_valid */
void test_valid_blockchain_node() {

	printf(blockchain_node_is_valid(test));
}

/*Wrote helper function to determine if a block is valid. It changes the is_valid field to true if it is. */
/* To check if a block is valid, we must check:
 * - height:
 		genesis block OR
 		parent must be valid
 * - hash of the block
 * - height of transactions equal block's height
 * - reward transactions are not signed and don't come from another public key
 * - normal transaction in the block
 		transaction referenced must exist
 		signature is valid
 		coin must not have already been spent
*/
bool blockchain_node_is_valid(blockchain_node node) {
	hash_output h;
	block_hash(*node->b, h);
	uint32_t blocks_height = node->b->height;

    if (blocks_height == 0 && byte32_cmp(GENESIS_BLOCK_HASH, h) != 0) { 
        return false; 
        //is the genesis block, but SHA256 hash isn't the right value
    } else if (blocks_height >= 1 && node->parent->is_valid == false || node->parent->b->height != (blocks_height - 1))) {
    	return false; 
    	//isn't the genesis block and its parent isn't valid or doesn't have a height that is 1 smaller
    } else if (hash_output_is_below_target(hash_output) == 0) {
        return false; 
        //hash of the block is >= TARGET_HASH
    } else if (node->b->reward_tx->height != blocks_height || node->b->normal_tx->height != blocks_height) {
    	return false;
    	//height of either of the block's transactions aren't equal to the block's height
    } else if (byte32_is_zero(node->b->reward_tx->prev_transaction_hash) == 0 || byte32_is_zero(node->b->reward_tx->src_signature->r) == 0 || byte32_is_zero(node->b->reward_tx->src_signature->s) ==0) {
        return false;
        //reward_tx's prev_transaction_hash, src_signature.r, or src_signature.s are not all 0
    } else if (node->b->normal_tx->prev_transaction_hash != 0) {
    	//there is a normal transaction in the block, so we need to check a bunch more stuff:
    	
    	blockchain_node n = node;
    	int flag = 0;
    	int transaction_verify_result = 100; //changed to 0 if successful, -1 if runtime error, 0 if invalid
    	//flag changes to 1 if normal_tx.prev_transaction_hash exists as either the reward_tx or normal_tx of any ancestor blocks
    	hash_output r_tx;
    	hash_output n_tx;
    	
    	while (n->parent) { //while you haven't gone through all of the nodes
    		transaction_hash(n->parent->b->reward_tx, r_tx);
    		transaction_hash(n->parent->b->normal_tx, n_tx);

    		if (r_tx == node->b->normal_tx->prev_transaction_hash) { 
    			//the transaction matches the normal_tx of this ancestor block
    			flag = 1;
    			if (transaction_verify(*node->b->normal_tx, *n_tx) != 1)) {
					if (transaction_verify(*node->b->normal_tx, *n_tx) == -1) {
						printf("RUNTIME ERROR FOR transaction_verify\n");
					}
				return false;
			//signature on normal_tx isn't valid using the dest_pubkey of the previous transaction that has hash value normal_tx.prev_transaction_hash
    			}
    		
    		break;

    		} else if(n_tx == node->b->reward_tx->prev_transaction_hash){
    			//the transaction matches the reward_tx of this ancestor block -- do the same thing as before but with r_tx
    			flag = 1;
    			if (transaction_verify(*node->b->normal_tx, *r_tx) != 1)) {
					if (transaction_verify(*node->b->normal_tx, *r_tx) == -1) {
						printf("RUNTIME ERROR FOR transaction_verify\n");
					}
				return false;
			//signature on normal_tx isn't valid using the dest_pubkey of the previous transaction that has hash value normal_tx.prev_transaction_hash
    			}

    		break;

    		} else if (n->parent->b->normal_tx->prev_transaction_hash == node->b->normal_tx->prev_transaction_hash) {
    			return false;
    			//this ancestor block has the same normal_tx.prev_transaction_hash, so the coin has already been spent
    		} else {
    		n = n->parent; //continue backtracking
    		}
    	}
    	if (flag == 0) { 
    		return false;
    	}
    } //close this giant if block
	//made it!
	return true;
}


int main(int argc, char *argv[])
{
	int i;

	/* Read input block files. */
	for (i = 1; i < argc; i++) {
		char *filename;
		struct block b;
		int rc;

		filename = argv[i];
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}

		/* TODO */
		/* Feel free to add/modify/delete any code you need to. */
	}

	/* Organize into a tree, check validity, and output balances. */
	/* TODO */
    if (blockchain_node_is_valid(node)) {
        //organize into a tree
    }

	struct balance *balances = NULL, *p, *next;
	/* Print out the list of balances. */
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	return 0;
}
