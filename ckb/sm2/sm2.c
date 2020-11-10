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

static int sm2_sig_verify(const EC_GROUP *group, const char *xP, const char *yP,const char *r,const char *s,unsigned char *dgst_test,size_t dgstlen)
{
	int ret = 0;
	EC_KEY *pubkey = NULL;
	ECDSA_SIG *sig;
	BIGNUM *sig_r = NULL;
	BIGNUM *sig_s = NULL;

	BN_hex2bn(&sig_r,r);//sig r
	BN_hex2bn(&sig_s,s);//sig s

	if (!(sig = ECDSA_SIG_new())) 
	{
		goto err;
	}

	if (!(ECDSA_SIG_set0(sig,sig_r,sig_s))) 
	{
		goto err;
	}


	if (!(pubkey = new_ec_key(group, NULL, xP, yP))) 
	{
		goto err;
	}


	if (1 != SM2_do_verify(dgst_test, dgstlen,sig, pubkey)) 
	{
		goto err;
	}
	ret = 1;
err:
	if (pubkey) EC_KEY_free(pubkey);
	return ret;
}

static int sm2_sm3_sig_verify(const EC_GROUP *group, const char *xP, const char *yP,const char *r,const char *s,const unsigned char *M,size_t Mlen,const char *id,size_t idlen)
{
	int ret = 0;
	EC_KEY *pubkey = NULL;
	ECDSA_SIG *sig;
	BIGNUM *sig_r = NULL;
	BIGNUM *sig_s = NULL;
	const EVP_MD *id_md = EVP_sm3();
	const EVP_MD *msg_md = EVP_sm3();
	unsigned char dgst[EVP_MAX_MD_SIZE];
	size_t dgstlen = sizeof(dgst);

	BN_hex2bn(&sig_r,r);//sig r
	BN_hex2bn(&sig_s,s);//sig s

	if (!(sig = ECDSA_SIG_new())) 
	{
		goto err;
	}

	if (!(ECDSA_SIG_set0(sig,sig_r,sig_s))) 
	{
		goto err;
	}


	if (!(pubkey = new_ec_key(group, NULL, xP, yP))) 
	{
		goto err;
	}


	if (!SM2_compute_message_digest(id_md, 
	msg_md,
	M, 
	Mlen, 
	id, 
	idlen,
	dgst, 
	&dgstlen, 
	pubkey)) 
	{
		goto err;
	}


	if (1 != SM2_do_verify(dgst, dgstlen,sig, pubkey)) 
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
	int err = 0,suc = 0;
	EC_GROUP *sm2p256 = NULL;
	unsigned char dgst_test[] = {0XF0,0XB4,0X3E,0X94,0XBA,0X45,0XAC,0XCA,0XAC,0XE6,0X92,0XED,0X53,0X43,0X82,0XEB,0X17,0XE6,0XAB,0X5A,0X19,0XCE,0X7B,0X31,0XF4,0X48,0X6F,0XDF,0XC0,0XD2,0X86,0X40};
	size_t dgstlen = sizeof(dgst_test);

//	This is the official standard parameter of SM2 algorithm,which also can be changed.
	sm2p256 = new_ec_group(1,
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",  
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",  
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",  
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",  
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
		"1");
	if ( !sm2p256 ) 
	{
		err++;
		return 1;
	}

	if (!sm2_sig_verify(sm2p256,
	"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020",//public key x
	"CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13",//public key y
	"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3",//sig r
	"B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA",//sig s
	dgst_test,//eg. dgst_test = sm3(M + sm3(id + sm2 parameter + public key))
	dgstlen)) 
	{
		printf("sm2 sign real failed\n");
		err++;
		return 2;
	} 
	else 
	{
		suc++;
	}


	if (!sm2_sm3_sig_verify(sm2p256,
	"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020",//publik key x
	"CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13",//public key y
	"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3",//sig r
	"B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA",//sig s
	(const unsigned char *)"message digest",//Message
	strlen("message digest"),
	"1234567812345678",//user id
	strlen("1234567812345678")
	)) 
	{
		err++;
		return 3;
	} 
	else 
	{
		suc++;
		return 4;
	}
//*/
	return suc;
end:
	return 0;
}
