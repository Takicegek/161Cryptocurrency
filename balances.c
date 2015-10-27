#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/ec.h>
#include <openssl/objects.h>

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
	struct ecdsa_pubkey *transaction_parent_key;
	struct block b;
	bool is_valid;
};

/* Add a block as a blockchain_node to a storage list of blockchain_nodes. */
void save_block(struct blockchain_node *head, struct block *element, struct blockchain_node **list) {
	struct blockchain_node *new_node;
	new_node = malloc(sizeof(struct blockchain_node));
	new_node->next = NULL;
	new_node->parent = NULL;
	new_node->b = *element;
	new_node->is_valid = false;

	struct blockchain_node *iter = head;
	if (iter == NULL) {
		*list = new_node;
	}
	else {	
		while(iter->next != NULL) {
			iter = iter->next;
		}
		iter->next = new_node;
	}

}

/* Remove blockchain_node ELEMENT from linked list HEAD. */
void remove_blockchain_node(struct blockchain_node *head, struct blockchain_node *element) {
	if (element == head) {
		head = head->next;
	}
	else {
		struct blockchain_node *prev = head;
		struct blockchain_node *iter = head->next;
		while (iter != NULL) {
			if (iter == element) {
				prev->next = iter->next;
			}
			prev = iter;
			iter = iter->next;
		}
	}
}

/* Returns a valid parent that matches the provided HASH value within the given list HEAD. Returns 
 * NULL if none is found. */
struct blockchain_node *find_parent(struct block *child, struct blockchain_node *head) {
	struct blockchain_node *iter = head;
	struct block *current;
	hash_output h;
	while (iter != NULL) {
		current = &iter->b;
		if (current->height == child->height - 1) {
			block_hash(current, h);
			if (byte32_cmp(child->prev_block_hash, h) == 0) {
				return iter;
			}
		}
		iter = iter->next;
	}
	return NULL;
}

/* Checks if node ELEMENT and all its ancestors up to the genesis block are valid. */
bool check_chain(struct blockchain_node *element) {
	struct blockchain_node *iter = element;
	while (iter != NULL) {
		if (element->is_valid != true) {
			return false; 
		}
		iter = iter->next;
	}
	return true;
}

/* Wrote helper function to determine if a block is valid. It changes the is_valid field to true if it is. */
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
bool blockchain_node_is_valid(struct blockchain_node *node) {
    hash_output h;
    struct block *bl_ptr = &node->b;
    block_hash(&node->b, h);
    uint32_t blocks_height = bl_ptr->height;

    if (blocks_height == 0 && byte32_cmp(GENESIS_BLOCK_HASH, h) != 0) {

        return false;
        //is the genesis block, but SHA256 hash isn't the right value
    } else if (blocks_height >= 1 && (node->parent == NULL || (node->parent->is_valid == false || node->parent->b.height != (blocks_height - 1)))) {

        return false;
        //isn't the genesis block and its parent isn't valid or doesn't have a height that is 1 smaller
    } else if (hash_output_is_below_target(h) == 0) {

        return false;
        //hash of the block is >= TARGET_HASH
    } else if (bl_ptr->reward_tx.height != blocks_height || bl_ptr->normal_tx.height != blocks_height) {

        return false;
        //height of either of the block's transactions aren't equal to the block's height
    } else if (byte32_is_zero(bl_ptr->reward_tx.prev_transaction_hash) == 0 || byte32_is_zero(bl_ptr->reward_tx.src_signature.r) == 0 || byte32_is_zero(bl_ptr->reward_tx.src_signature.s) ==0) {

        return false;
        //reward_tx's prev_transaction_hash, src_signature.r, or src_signature.s are not all 0
    } else if (byte32_is_zero(bl_ptr->normal_tx.prev_transaction_hash) == 0) {
        //there is a normal transaction in the block, so we need to check a bunch more stuff:

        struct blockchain_node *ancestor = node->parent;
        int flag = 0;
        //flag changes to 1 if normal_tx.prev_transaction_hash exists as either the reward_tx or normal_tx of any ancestor blocks
        hash_output r_tx;
        hash_output n_tx;
        
        while (ancestor) { //while you haven't gone through all of the nodes
            transaction_hash(&(ancestor->b.reward_tx), r_tx);
            transaction_hash(&(ancestor->b.normal_tx), n_tx);
            
            if (byte32_cmp(n_tx, bl_ptr->normal_tx.prev_transaction_hash) == 0) {
                //the transaction matches the normal_tx of this ancestor block
                flag = 1;
                node->transaction_parent_key = &ancestor->b.normal_tx.dest_pubkey;

                if (transaction_verify(&bl_ptr->normal_tx, &ancestor->b.normal_tx) != 1) {
                    return false;
                    //signature on normal_tx isn't valid using the dest_pubkey of the previous transaction that has hash value normal_tx.prev_transaction_hash
                }
                
                break;
                
            } else if(byte32_cmp(r_tx, bl_ptr->normal_tx.prev_transaction_hash) == 0) {
            	//the transaction matches the reward_tx of this ancestor block -- do the same thing as before but with r_tx
            	flag = 1;
                node->transaction_parent_key = &ancestor->b.reward_tx.dest_pubkey;

                if (transaction_verify(&bl_ptr->normal_tx, &ancestor->b.reward_tx) != 1) {
                    return false;
                    //signature on normal_tx isn't valid using the dest_pubkey of the previous transaction that has hash value normal_tx.prev_transaction_hash
                }
                
                break;
                
            } else if (byte32_cmp(ancestor->b.normal_tx.prev_transaction_hash, bl_ptr->normal_tx.prev_transaction_hash) == 0) {
                return false;
                //this ancestor block has the same normal_tx.prev_transaction_hash, so the coin has already been spent
            } else {
                ancestor = ancestor->parent; //continue backtracking
            }
        }
        if (flag == 0 && blocks_height != 0) {
            return false;
        } 
    } //close this giant if block
    //made it!
    return true;
}

/* Checks if a blockchain_node ELEMENT is valid and changes the is_valid field if it is.*/
void validify_node(struct blockchain_node *element) {
	if (blockchain_node_is_valid(element)) {
		element->is_valid = true;
	}
}

/* Manages a unsorted list HEAD of blockchain_nodes to match a tree structure. Does so by:
 * 1) Assigning each block's parent
 * 2) Verifying that each block is valid 
 * 3) Returning the final blockchain_node with the largest height in the longest valid chain. */
struct blockchain_node *process_blockchain(struct blockchain_node *head) {
	struct blockchain_node *iter = head;
	struct block *current;

	while (iter != NULL) {
		current = &iter->b;
		if (current->height != 0) {
			iter->parent = find_parent(current, head);		
		}
		iter = iter->next;
	}

	uint32_t curr_height = 0;
	int flag = 1;
	while (flag == 1) {
		iter = head;
		flag = 0;
		while (iter != NULL) {
			if (iter->b.height == curr_height) {
				flag = 1;
				validify_node(iter);
			}
			iter = iter->next;	
		}
		curr_height++;
	}

	uint32_t chain_height = curr_height - 2;

	iter = head;
	while (iter != NULL) {
		current = &iter->b;
		if (current->height == chain_height) {
			if (check_chain(iter)) {
				return iter;
			}
		}
		iter = iter->next;
	}
	return NULL;
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

/* Inverts a linked list of blockchain_nodes at HEAD given the pointer to the pointer HEAD_POINTER. */
void invert_list(struct blockchain_node *head, struct blockchain_node **head_pointer) {
	struct blockchain_node *hold;
	struct blockchain_node *new_list = NULL;
	while (head != NULL) {
		hold = head;
		head = head->parent;
		hold->parent = new_list;
		new_list = hold;
	}
	*head_pointer = new_list;
}

/* STEP 2: Mine a new block that transfers a coin from the weak public key to mykey.priv
 * Function that steals a coin from another transaction in FROMBLOCK with a weak public key and rewards it to they public
 * key in mykey.priv. Builds upon the blockchain_node HEADBLOCK of the longest chain. Will steal from block 4 or block 5 
 * depending on WHICH. */
void steal_block(struct blockchain_node *headblock, struct blockchain_node *fromblock, int which) {
	struct block newblock;
	/* Build on top of the head of the main chain. */
	block_init(&newblock, &headblock->b);
	/* Give the reward to us. */
	FILE *my_key_fp = fopen("mykey.priv", "r");
	transaction_set_dest_privkey(&newblock.reward_tx, key_read(my_key_fp));
	fclose(my_key_fp);
	/* The last transaction was in block 4. */
	transaction_set_prev_transaction(&newblock.normal_tx, &fromblock->b.normal_tx);
	/* Send it to us. */
	my_key_fp = fopen("mykey.priv", "r");
	transaction_set_dest_privkey(&newblock.normal_tx, key_read(my_key_fp));
	fclose(my_key_fp);
	/* Sign it with the guessed private key. */
	FILE *guessed_key_fp;
	if (which == 1) {
		guessed_key_fp = fopen("copykey.priv", "r");
	}
	else {
		guessed_key_fp = fopen("copykey2.priv", "r");
	}
	transaction_sign(&newblock.normal_tx, key_read(guessed_key_fp));
	fclose(guessed_key_fp);
	/* Mine the new block. */
	block_mine(&newblock);
	/* Save to a file. */
	if (which == 1) {
		block_write_filename(&newblock, "myblock1.blk");
	}
	else {
		block_write_filename(&newblock, "myblock2.blk");
	}
}

int main(int argc, char *argv[])
{
	int i;
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
			save_block(unsorted, &b, &unsorted); // Save block to chain
	}

	struct blockchain_node *longest = process_blockchain(unsorted);
	if (longest == NULL) {
		fprintf(stderr, "Error processing blocks.\n");
		return 1;
	}

	// struct blockchain_node *st_headblock = longest; // Code for stealing blocks

	invert_list(longest, &longest);

	struct balance *balances = NULL, *p, *next;
	while (longest != NULL) {
		/*if (longest->b.height == 4) { // Code for stealing blocks
			printf("Stealing first block at height = 4.\n");
			steal_block(st_headblock, longest, 1);
		}*/
		/*if (longest->b.height == 5) { // Code for stealing blocks
			printf("Stealing second block at height = 5.\n");
			steal_block(st_headblock, longest, 2);
		}*/
		balances = balance_add(balances, &longest->b.reward_tx.dest_pubkey, 1); // Reward increment
		if (byte32_is_zero(longest->b.normal_tx.prev_transaction_hash) != 1) {
			balances = balance_add(balances, &longest->b.normal_tx.dest_pubkey, 1); // Transaction increment
			if (&longest->transaction_parent_key != NULL) {
				balances = balance_add(balances, longest->transaction_parent_key, -1); // Transaction decrement
			}
		}
		longest = longest->parent;
	}

	/* Print out the list of balances. */
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	struct blockchain_node *hold;
	while(unsorted) {
		hold = unsorted;
		unsorted = unsorted->next;
		free(hold);
	}

	return 0;
}
