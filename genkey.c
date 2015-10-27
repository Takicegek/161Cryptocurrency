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

/*STEP 2 generate copy key using weak PRNG */
/* Desired normal_tx destination from == BLOCK 0000005ef8689e29b57aea00695141bfabcd63a7a9d311270c63b76a2fc2e2f3 ==
		in file 2fc2e2f3.blk
 	*dest_pubkey_x = d8a9b4c603833a8586c5389e167d25e9e5dd33ad3c2c95be1c35c2dcded699b5;
 	*dest_pubkey_y = 67ed4bd4dc7eee5d8789fd7d3d2af96dbdfb967911fd812d9c5fc5486c9aea1f;
*/
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

/*STEP 2 generate copy key using a time-based PRNG seed */
/* Desired normal_tx destination from BLOCK 000000c55643cbb82ec2942d2fa023d1a94dc23344c6467f6b0c4db2c907b60e
		in file c907b60e.blk
 	dest_pubkey_x = bd63383861d845b62637f221ca3b4cc21d1f82d5c0e018b8f2fc2906702c4f1b
 	dest_pubkey_y = 17e6cb83581672fd7d690c5416a50d2a0aaf3d9ea961761ab7000140bea78218
*/
static EC_KEY *generate_copy_key_timebased(int t)
{
	unsigned char buf[32];
	int i;

	srand(t);
		for (i = 0; i < 32; i++) {
			buf[i] = rand() & 0xff;
		}
	return generate_key_from_buffer(buf);
}

int main(int argc, char *argv[])
{

	/*modified main function for step 2, 2nd key */
	const char *filename;
	EC_KEY *key;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "need an output filename\n");
		exit(1);
	}

	filename = argv[1];

	//source for time in seconds: http://www.timeanddate.com/date/timezoneduration.html?d1=1&m1=1&y1=1970&h1=0&i1=0&s1=0
	//estimated time is 1443700800, but start 14 hours before (in seconds)
	int t = 1443700800 - 50400;

	//CREATE TARGET KEY X AND Y (by converting)
	BIGNUM *target_x = BN_new();
	BIGNUM *target_y = BN_new();

	if (target_x == NULL || target_y == NULL) {
		printf("BIGNUM target errors for target_y or target_x \n");
		BN_free(target_x);
		BN_free(target_y);
		exit(1);
	}

	char str_y[64] = "17E6CB83581672FD7D690C5416A50D2A0AAF3D9EA961761AB7000140BEA78218";
	BN_hex2bn(&target_y, str_y);

	char str_x[64] = "BD63383861D845B62637F221CA3B4CC21D1F82D5C0E018B8F2FC2906702C4F1B";
	BN_hex2bn(&target_x, str_x);

	//GENERATE KEY FOR THE FIRST TIME + WRITE TO FILE
	key = generate_copy_key_timebased(t);
	rc = key_write_filename(filename, key);
	if (rc != 1) {
		fprintf(stderr, "error saving key\n");
		exit(1);
	}

	//GETTING THE COORDINATES OF THE KEY GENERATED
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	if (x == NULL || y == NULL) {
		printf("x or y errors\n");
		BN_free(x);
		BN_free(y);
		EC_KEY_free(key);
		exit(1);
	}

	const EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(EC_GROUP_NID);
	//printf("finished making EC_GROUP\n");

	const EC_POINT *pubkey;

	FILE *fp;
	fp = fopen(filename, "r");

	pubkey = EC_KEY_get0_public_key(key_read(fp)); 
	if (pubkey == NULL) {
		EC_KEY_free(key);
		printf("error in EC_POINT pubkey\n");
		exit(1);
	}

	//printf("finished making EC_POINT, got to before call function\n");

	int get_pt_result = 1000;
 	get_pt_result = EC_POINT_get_affine_coordinates_GFp(ec_group, pubkey, x, y, NULL);
	if (get_pt_result != 1) {
		printf("error with the big function\n");
		BN_free(x);
		BN_free(y);
		EC_KEY_free(key);
		exit(1);
	} else {
		//printf("got here, right before printing\n");
		printf("X coordinates are:\n");
		BN_print_fp(stdout, x);
	    putc('\n', stdout);
	    BN_print_fp(stdout, target_x);
	    putc('\n', stdout);

		printf("Y coordinates are:\n");
	     BN_print_fp(stdout, y);
	     putc('\n', stdout);
	     BN_print_fp(stdout, target_y);
	     putc('\n', stdout);
	     putc('\n', stdout);
    }

    //CHECK IF THE KEY IS WHAT WE WANT, AND IF NOT, KEEP LOOPING AND CHECKING
    int x_cmp_result = BN_cmp(x, target_x);
    int y_cmp_result = BN_cmp(y, target_y);

	while (x_cmp_result != 0 || y_cmp_result != 0) { 
		fclose(fp);
		t = t+1;

		if (t == 1443700800 + 50400) {
			//already searched from 14 hours before target time to 14 hours after
			printf("COULDN'T FIND :(\n");
			exit(1);
		}

		key = generate_copy_key_timebased(t);
		if (key == NULL) {
			fprintf(stderr, "error generating key in while\n");
			exit(1);
		}
		rc = key_write_filename(filename, key);
		if (rc != 1) {
			fprintf(stderr, "error saving key in while\n");
			exit(1);
		}

		fp = fopen(filename, "r");

		pubkey = EC_KEY_get0_public_key(key_read(fp)); 
		if (pubkey == NULL) {
			EC_KEY_free(key);
			printf("error in EC_POINT pubkey in while\n");
			exit(1);
		}

		//printf("finished making EC_POINT, got to before call function in while\n");

		get_pt_result = 1000; //reinitialize
		BN_clear(x);
		BN_clear(y);

	 	get_pt_result = EC_POINT_get_affine_coordinates_GFp(ec_group, pubkey, x, y, NULL);
		if (get_pt_result != 1) {
			printf("error with the big function in while\n");
			BN_free(x);
			BN_free(y);
			EC_KEY_free(key);
			exit(1);
		} else {
			//printf("got here, right before printing in while\n");
			printf("X coordinates are:\n");
	        BN_print_fp(stdout, x);
	        putc('\n', stdout);
	        BN_print_fp(stdout, target_x);
	        putc('\n', stdout);

	        printf("Y coordinates are:\n");
	        BN_print_fp(stdout, y);
	        putc('\n', stdout);
	        BN_print_fp(stdout, target_y);
	        putc('\n', stdout);
	        putc('\n', stdout);

	    }

	    //set up comparison again for new key
	    x_cmp_result = BN_cmp(x, target_x);
    	y_cmp_result = BN_cmp(y, target_y);
	} //closes while loop
	

	printf("yay got the right key!!! finishing up...\n");

	fclose(fp);
	BN_free(x);
	BN_free(y);

	EC_KEY_free(key);

	/*modified main function for step 2, 1st key */
	/*const char *filename;
	EC_KEY *key;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "need an output filename\n");
		exit(1);
	}

	filename = argv[1];

	//FIRST KEY FOR HEIGHT 4 BLOCK
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

	int get_pt_result;

	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	
	if (x == NULL || y == NULL) {
		printf("x or y errors\n");
		BN_free(x);
		BN_free(y);
		EC_KEY_free(key);
		exit(1);
	}

	printf("finished making BIGNUMs x and y\n");

	const EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(EC_GROUP_NID);
	printf("finished making EC_GROUP\n");

	const EC_POINT *pubkey;

	FILE *fp;
	fp = fopen(filename, "r");

	pubkey = EC_KEY_get0_public_key(key_read(fp)); 
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

	fclose(fp);
	BN_free(x);
	BN_free(y);

	EC_KEY_free(key);
	*/


	/* main function for 1st key generation */

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
