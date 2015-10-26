#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

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
		printf("Assigned head to first node.\n");
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

/* Iterates through a linked list of blockchain_nodes to find the maximum height. */
uint32_t find_max_height(struct blockchain_node *head) {
	struct blockchain_node *iter = head;
	struct block *current;
	uint32_t max_height = 0;
	while (iter != NULL) {
		current = &iter->b;
		if (current->height > max_height) {
			max_height = current->height;
		}
		iter = iter->next;
	}
	return max_height;
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
	printf("No parent found.\n");
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
    printf("Begin validifying process for block of height:%u\n", blocks_height);
    
    if (blocks_height == 0 && byte32_cmp(GENESIS_BLOCK_HASH, h) != 0) {
    	    printf("is the genesis block, but SHA256 hash isn't the right value\n");

        return false;
        //is the genesis block, but SHA256 hash isn't the right value
    } else if (blocks_height >= 1 && (node->parent == NULL || (node->parent->is_valid == false || node->parent->b.height != (blocks_height - 1)))) {
    	    printf("its parent isn't valid or doesn't have a height that is 1 smaller\n");

        return false;
        //isn't the genesis block and its parent isn't valid or doesn't have a height that is 1 smaller
    } else if (hash_output_is_below_target(h) == 0) {
    	    printf("hash of the block is >= TARGET_HASH\n");

        return false;
        //hash of the block is >= TARGET_HASH
    } else if (bl_ptr->reward_tx.height != blocks_height || bl_ptr->normal_tx.height != blocks_height) {
    	    printf("height of either of the block's transactions aren't equal to the block's height\n");

        return false;
        //height of either of the block's transactions aren't equal to the block's height
    } else if (byte32_is_zero(bl_ptr->reward_tx.prev_transaction_hash) == 0 || byte32_is_zero(bl_ptr->reward_tx.src_signature.r) == 0 || byte32_is_zero(bl_ptr->reward_tx.src_signature.s) ==0) {
           printf("reward_tx's prev_transaction_hash, src_signature.r, or src_signature.s are not all 0\n");

        return false;
        //reward_tx's prev_transaction_hash, src_signature.r, or src_signature.s are not all 0
    } else if (byte32_is_zero(bl_ptr->normal_tx.prev_transaction_hash) == 0) {
        //there is a normal transaction in the block, so we need to check a bunch more stuff:
            printf("normal transaction found, checking more stuff.\n");

        struct blockchain_node *ancestor = node->parent;
        int flag = 0;
        //flag changes to 1 if normal_tx.prev_transaction_hash exists as either the reward_tx or normal_tx of any ancestor blocks
        hash_output r_tx;
        hash_output n_tx;
        
        while (ancestor) { //while you haven't gone through all of the nodes
            transaction_hash(&(ancestor->b.reward_tx), r_tx);
            transaction_hash(&(ancestor->b.normal_tx), n_tx);
                printf("start loop\n");

            
            if (byte32_cmp(n_tx, bl_ptr->normal_tx.prev_transaction_hash) == 0) {
                //the transaction matches the normal_tx of this ancestor block
                flag = 1;
                    printf("matching normal transaction of ancestor found. height of ancestor:%u\n", ancestor->b.height);

                printf("transaction verification output: %d\n", transaction_verify(&bl_ptr->normal_tx, &ancestor->b.normal_tx));
                if (transaction_verify(&bl_ptr->normal_tx, &ancestor->b.normal_tx) != 1) {
                	    printf("signature verification not successful.\n");

                    if (transaction_verify(&bl_ptr->normal_tx, &ancestor->b.normal_tx) == -1) {
                        printf("RUNTIME ERROR FOR transaction_verify\n");
                    }
                    return false;

                    //signature on normal_tx isn't valid using the dest_pubkey of the previous transaction that has hash value normal_tx.prev_transaction_hash
                }
                
                break;
                
            } else if(byte32_cmp(r_tx, bl_ptr->normal_tx.prev_transaction_hash) == 0) {
            	    printf("matching reward transaction of ancestor found. height of ancestor:%u\n", ancestor->b.height);

                //the transaction matches the reward_tx of this ancestor block -- do the same thing as before but with r_tx
                flag = 1;

                printf("transaction verification output: %d\n", transaction_verify(&bl_ptr->normal_tx, &ancestor->b.reward_tx));
                if (transaction_verify(&bl_ptr->normal_tx, &ancestor->b.reward_tx) != 1) {
                	    printf("signature verifiation not successful.\n");

                    if (transaction_verify(&bl_ptr->normal_tx, &ancestor->b.reward_tx) == -1) {
                        printf("RUNTIME ERROR FOR transaction_verify\n");
                    }
                    return false;
                    //signature on normal_tx isn't valid using the dest_pubkey of the previous transaction that has hash value normal_tx.prev_transaction_hash
                }
                
                break;
                
            } else if (byte32_cmp(ancestor->b.normal_tx.prev_transaction_hash, bl_ptr->normal_tx.prev_transaction_hash) == 0) {
            	    printf("coin already spent\n");

                return false;
                //this ancestor block has the same normal_tx.prev_transaction_hash, so the coin has already been spent
            } else {
                ancestor = ancestor->parent; //continue backtracking
            }
        }
        if (flag == 0 && blocks_height != 0) { 
        	    printf("no ancestor found\n");
            return false;
        } 
    } //close this giant if block
    //made it!
    return true;
}

/* Checks if a blockchain_node ELEMENT is valid and changes the is_valid field if it is.*/
void validify_node(struct blockchain_node *element) {
	if (blockchain_node_is_valid(element)) {
		printf("valid\n");
		element->is_valid = true;
	}
	else {
		printf("not valid\n");
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

	printf("Done finding all parents.\n");

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
	printf("Finished validifying all nodes. Longest chain is of height:%u\n", chain_height);

	iter = head;
	while (iter != NULL) {
		current = &iter->b;
		if (current->height == chain_height) {
			if (check_chain(iter)) {
				printf("Found end of chain.\n");
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

/* Finds the previous transaction for a transaction HASH in the given blockchain_node list CHAIN and 
 * returns the public key that received transaction. */
void decrement_prev_transaction(struct balance *balances, hash_output hash, struct blockchain_node *chain) {
	struct blockchain_node *iter = chain;
	hash_output h;
	while (iter != NULL) {
		transaction_hash(&iter->b.reward_tx, h);
		if (byte32_cmp(h, hash) == 0) {
			balances = balance_add(balances, &iter->b.reward_tx.dest_pubkey, -1);
		}
		transaction_hash(&iter->b.normal_tx, h);
		if (byte32_cmp(h, hash) == 0) {
			balances = balance_add(balances, &iter->b.normal_tx.dest_pubkey, -1);
		}
		iter = iter->parent;
	}
}

/*STEP 2: mine a new block that transfers a coin from the weak public key to mykey.priv */

/* Build on top of the head of the main chain. */
//block_init(&newblock, &headblock);
/* Give the reward to us. */
//transaction_set_dest_privkey(&newblock.reward_tx, mykey);
/* The last transaction was in block 4. */
//transaction_set_prev_transaction(&newblock.normal_tx, &block4.normal_tx);
/* Send it to us. */
//transaction_set_dest_privkey(&newblock.normal_tx, mykey);
/* Sign it with the guessed private key. */
//transaction_sign(&newblock.normal_tx, weakkey);
/* Mine the new block. */
//block_mine(&newblock);
/* Save to a file. */
//block_write_filename(&newblock, "myblock1.blk");


int main(int argc, char *argv[])
{
	int i;
	FILE *fp;
	fp = fopen("Output.txt", "w");
	struct blockchain_node *unsorted = NULL;
	//struct blockchain_node *sorted_tree = NULL;

	/* Read input block files. */
	for (i = 1; i < argc; i++) {
		printf("Current argv: %s\n", argv[i]);
		char *filename;
		struct block b;
		int rc;

		filename = argv[i];
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}

			block_print(&b, fp);
			save_block(unsorted, &b, &unsorted); // Save block to chain
			printf("Block added.\n");
	}

	/*struct blockchain_node *node = unsorted; // for debugging
	while(node->next != NULL) {
		block_print(&node->b, fp);
		node = node->next;
	}*/
	struct blockchain_node *longest = process_blockchain(unsorted);
	printf("Finished processing. Longest chain has end block of height:%u\n", longest->b.height);
	/*fprintf(fp, "\nThe block that corresponds to the longest valid chain is:\n");
	block_print(&longest->b, fp);*/
	fclose(fp);

	struct balance *balances = NULL, *p, *next;
	while (longest != NULL) {
		balances = balance_add(balances, &longest->b.reward_tx.dest_pubkey, 1); // Reward increment
		if (byte32_is_zero(longest->b.normal_tx.prev_transaction_hash) != 1){
			balances = balance_add(balances, &longest->b.normal_tx.dest_pubkey, 1); // Transaction increment
			decrement_prev_transaction(balances, longest->b.normal_tx.prev_transaction_hash, longest); // Transaction decrement
		}
		longest = longest->parent;
	}
	/* Print out the list of balances. */
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	struct blockchain_node *pointer; // Free memory from unsorted list
	for (pointer = unsorted; pointer != NULL; pointer = pointer->next) {
		free(pointer);
	}

	return 0;
}
