#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>
# include "../crypto/sm2/sm2_lcl.h"

static EC_GROUP *new_ec_group(int is_prime_field,
	const char *p_hex, const char *a_hex, const char *b_hex,
	const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
	int ok = 0;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	EC_POINT *G = NULL;
	point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
	int flag = 0;

	if (!(ctx = BN_CTX_new())) 
	{
		goto err;
	}

	if (!BN_hex2bn(&p, p_hex) ||
	    !BN_hex2bn(&a, a_hex) ||
	    !BN_hex2bn(&b, b_hex) ||
	    !BN_hex2bn(&x, x_hex) ||
	    !BN_hex2bn(&y, y_hex) ||
	    !BN_hex2bn(&n, n_hex) ||
	    !BN_hex2bn(&h, h_hex)) 
	{
		goto err;
	}

	if (is_prime_field) 
	{
		if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) 
		{
			goto err;
		}
		if (!(G = EC_POINT_new(group))) 
		{
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) 
		{
			goto err;
		}
	} else 
	{
		if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) 
		{
			goto err;
		}
		if (!(G = EC_POINT_new(group))) 
		{
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) 
		{
			goto err;
		}
	}

	if (!EC_GROUP_set_generator(group, G, n, h)) 
	{
		goto err;
	}

	EC_GROUP_set_asn1_flag(group, flag);
	EC_GROUP_set_point_conversion_form(group, form);

	ok = 1;
err:
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(n);
	BN_free(h);
	EC_POINT_free(G);
	if (!ok && group) 
	{
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		group = NULL;
	}

	return group;
}

static EC_KEY *new_ec_key(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP)
{
	int ok = 0;
	EC_KEY *ec_key = NULL;
	BIGNUM *d = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	if (!(ec_key = EC_KEY_new()))
	{
		goto end;
	}
	if (!EC_KEY_set_group(ec_key, group)) 
	{
		goto end;
	}

	if (sk) 
	{
		if (!BN_hex2bn(&d, sk)) 
		{
			goto end;
		}
		if (!EC_KEY_set_private_key(ec_key, d)) 
		{
			goto end;
		}
	}

	if (xP && yP) 
	{
		if (!BN_hex2bn(&x, xP)) 
		{
			goto end;
		}
		if (!BN_hex2bn(&y, yP)) 
		{
			goto end;
		}
		if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) 
		{
			goto end;
		}
	}
	ok = 1;
end:
	if (d) BN_free(d);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (!ok && ec_key) 
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ec_key;
}

static int test_sm2_sign(const EC_GROUP *group, const char *xP, const char *yP)
{
	int ret = 0;
	int type = NID_undef;
	size_t dgstlen;
	size_t siglen;

	EC_KEY *pubkey = NULL;
	unsigned char dgst_test[] = {0xb5,0x24,0xf5,0x52,0xcd,0x82,0xb8,0xb0,0x28,0x47,0x6e,0x00,0x5c,0x37,0x7f,0xb1,0x9a,0x87,0xe6,0xfc,0x68,0x2d,0x48,0xbb,0x5d,0x42,0xe3,0xd9,0xb9,0xef,0xfe,0x76};
	unsigned char sig_test[] = {0x30,0x44,0x02,0x20,0x40,0xf1,0xec,0x59,0xf7,0x93,0xd9,0xf4,0x9e,0x09,0xdc,0xef,0x49,0x13,0x0d,0x41,0x94,0xf7,0x9f,0xb1,0xee,0xd2,0xca,0xa5,0x5b,0xac,0xdb,0x49,0xc4,0xe7,0x55,0xd1,0x02,0x20,0x6f,0xc6,0xda,0xc3,0x2c,0x5d,0x5c,0xf1,0x0c,0x77,0xdf,0xb2,0x0f,0x7c,0x2e,0xb6,0x67,0xa4,0x57,0x87,0x2f,0xb0,0x9e,0xc5,0x63,0x27,0xa6,0x7e,0xc7,0xde,0xeb,0xe7};
	dgstlen = sizeof(dgst_test);
	siglen = sizeof(sig_test);

	if (!(pubkey = new_ec_key(group, NULL, xP, yP))) 
	{
		goto err;
	}

	if (1 != SM2_verify(type, dgst_test, dgstlen, sig_test, siglen, pubkey)) 
	{
		goto err;
	}
	ret = 1;
err:
	if (pubkey) EC_KEY_free(pubkey);
	return ret;
}

int main(int argc, char **argv)
{
	int err = 0;
	EC_GROUP *sm2p256test = NULL;

	sm2p256test = new_ec_group(1,
		"8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
		"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
		"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
		"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
		"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
		"8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
		"1");
	if ( !sm2p256test ) 
	{
		err++;
		goto end;
	}

	if (!test_sm2_sign(sm2p256test,"0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A","7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857")) 
	{
		printf("sm2 sign p256 failed\n");
		err++;
	} 
	else 
	{
		printf("sm2 sign p256 passed\n");
	}
end:
	EC_GROUP_free(sm2p256test);
	return 0;
}
