#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "common.h"

/* Usage: genkey FILENAME
 * Generate a key and write it to the file FILENAME. */

/* Interpret the 256 bits in buf as a private key and return an EC_KEY *. */
static EC_KEY *generate_key_from_buffer(const unsigned char buf[32])
{
	EC_KEY *key;
	BIGNUM *bn;
	int rc;

	key = NULL;
	bn = NULL;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		goto err;

	bn = BN_bin2bn(buf, 32, NULL);
	if (bn == NULL)
		goto err;

	rc = EC_KEY_set_private_key(key, bn);
	if (rc != 1)
		goto err;

	BN_free(bn);

	return key;

err:
	if (key != NULL)
		EC_KEY_free(key);
	if (bn != NULL)
		BN_free(bn);
	return NULL;
}

/* Generate a key using EC_KEY_generate_key. */
static EC_KEY *generate_key(void)
{
	EC_KEY *key;
	int rc;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		return NULL;
	rc = EC_KEY_generate_key(key);
	if (rc != 1) {
		EC_KEY_free(key);
		return NULL;
	}
	return key;
}

/*STEP 2*/
static EC_KEY *generate_identical_key(void)
{
	unsigned char buf[32];
	int i;
	srand(1234);
	for (i = 0; i < 32; i++) {
		buf[i] = rand() & 0xff;
	}
	return generate_key_from_buffer(buf);
}

int main(int argc, char *argv[])
{
	/*modified main function for step 2 */
	const char *filename;
	EC_KEY *key;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "need an output filename\n");
		exit(1);
	}

	filename = argv[1];
	printf("Starting main function and got file to be: %s\n", filename);

	key = generate_identical_key();
	if (key == NULL) {
		fprintf(stderr, "error generating key\n");
		exit(1);
	}

	rc = key_write_filename(filename, key);
	if (rc != 1) {
		fprintf(stderr, "error saving key\n");
		exit(1);
	}


	/* Desired normal_tx destination from == BLOCK 0000005ef8689e29b57aea00695141bfabcd63a7a9d311270c63b76a2fc2e2f3 ==
		in file 2fc2e2f3.blk
  */
		/*
 	unsigned char *dest_pubkey_x;
 	unsigned char *dest_pubkey_y;
 	*dest_pubkey_x = d8a9b4c603833a8586c5389e167d25e9e5dd33ad3c2c95be1c35c2dcded699b5;
 	*dest_pubkey_y = 67ed4bd4dc7eee5d8789fd7d3d2af96dbdfb967911fd812d9c5fc5486c9aea1f;
*/
	printf("finished all key stuff, now trying to compare\n");

	int get_pt_result;

	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	printf("called BN_new\n");
	
	if (x == NULL || y == NULL) {
		printf("x or y errors\n");
		BN_free(x);
		BN_free(y);
		EC_KEY_free(key);
		exit(1);
	}

	printf("finished making BIGNUMs x and y\n");

	//const EC_GROUP *ec_group = EC_KEY_get0_group(key);
	const EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(EC_GROUP_NID); //trying this instead
	printf("finished making EC_GROUP\n");

	const EC_POINT *pubkey;
	//pubkey = EC_KEY_get0_public_key(key);
	pubkey = EC_POINT_new(EC_KEY_get0_group(key)); 
	if (pubkey == NULL) {
		EC_KEY_free(key);
		printf("error in EC_POINT pubkey\n");
		exit(1);
	}

	printf("finished making EC_POINT, got to before call function\n");
 	get_pt_result = EC_POINT_get_affine_coordinates_GFp(ec_group, pubkey, x, y, NULL);
	if (get_pt_result != 1) {
		printf("error with the big function\n");
		BN_free(x);
		BN_free(y);
		EC_KEY_free(key);
		exit(1);
	} else {
		printf("got here, right before printing\n");
        BN_print_fp(stdout, x);
        putc('\n', stdout);
        BN_print_fp(stdout, y);
        putc('\n', stdout);
    }
/*
	if (bn2bin(x, dest_pubkey_x, sizeof(dest_pubkey_x)) != 1)
		goto err;
	if (bn2bin(y, dest_pubkey_y, sizeof(dest_pubkey_y)) != 1)
		goto err;
*/
	BN_free(x);
	BN_free(y);

	EC_KEY_free(key);

	/*original main function
	const char *filename;
	EC_KEY *key;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "need an output filename\n");
		exit(1);
	}

	filename = argv[1];

	key = generate_key();
	if (key == NULL) {
		fprintf(stderr, "error generating key\n");
		exit(1);
	}

	rc = key_write_filename(filename, key);
	if (rc != 1) {
		fprintf(stderr, "error saving key\n");
		exit(1);
	}

	EC_KEY_free(key);

	return 0;
	*/
	return 1;
}
