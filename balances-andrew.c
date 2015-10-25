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
	struct blockchain_node *next;
	struct block b;
	int is_valid;
};

/* Add a block to a storage list of blockchain_nodes. */
void save_block(struct blockchain_node *head, struct block *element) {
	struct blockchain_node *new_node;
	new_node = malloc(sizeof(struct blockchain_node));
	new_node->next = NULL;
	new_node->b = *element;
	new_node->is_valid = 0;

	struct blockchain_node *iter = head;
	while(iter->next != NULL) {
		iter = iter->next;
	}
	iter->next = new_node;
	new_node->parent = iter;
}

/* Naively organizes a unsorted list OLD to a new list TARGET based on height. 
 * Checks for validity of each block in the process. */
void sort_blockchain(struct blockchain_node *old, struct blockchain_node *target) {
	struct blockchain_node *old_iter = old;
	struct blockchain_node *old_prev = NULL;
	struct blockchain_node *new_iter = target;
	struct block *current;
	uint32_t curr_height = 0;

	while (old_iter != NULL) {
		current = &old_iter->b;
		if (current->height == curr_height) {
			// Need to check hash
			new_iter = old_iter; // set target to point to genesis block
			new_iter->parent = NULL;

			if(prev == NULL) {
				head = iter->parent; // Case where first item in list is genesis
			}
			else {
				prev->parent = iter->parent; // Else just remove from list
			}
		}
		prev = iter; // Increment prev
		iter = iter->parent; //Increment iter
	}
}

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

int main(int argc, char *argv[])
{
	int i;
	FILE *fp;
	fp = fopen("Output.txt", "w");
	struct blockchain_node *unsorted = NULL;
	//struct blockchain_node *sorted_tree = NULL;

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
		if (unsorted == NULL) { // Add first node to chain
		struct blockchain_node *first_node;
		first_node = malloc(sizeof(struct blockchain_node));
		first_node->parent = NULL;
		first_node->next = NULL;
		first_node->b = b;
		first_node->is_valid = 0;
		unsorted = first_node;
		}
		else {
			save_block(unsorted, &b); // Else add next node to growing chain
		}
	}

	/* Organize into a tree, check validity, and output balances. */
	/* TODO */
	struct blockchain_node *node = unsorted; // for debugging
	while(node->next != NULL) {
		block_print(&node->b, fp);
		node = node->next;
	}
	fclose(fp);

	//sort_blockchain(unsorted, sorted_tree);

	struct blockchain_node *pointer; // Free memory from unsorted list
	for (pointer = unsorted; pointer != NULL; pointer = pointer->next) {
		free(pointer);
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
