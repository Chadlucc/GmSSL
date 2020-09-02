#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sm2.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <openssl/is_gmssl.h>
EC_KEY *EC_KEYGenerate(void)
{
	EC_KEY *ret;
	if (!(ret = OPENSSL_malloc(sizeof(EC_KEY)))
		|| !(ret->ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))
		|| !EC_KEY_generate_key(ret->ec_key)) {
		ERR_print_errors_fp(stderr);
		EC_KEYFree(ret);
		return NULL;
	}
	return ret;
}

EC_KEY *EC_KEYFromPEM(FILE *fp, const char *password)
{
	EC_KEY *ret;
	EVP_PKEY *pkey = NULL;
	if (!(ret = OPENSSL_malloc(sizeof(EC_KEY)))
		|| !(pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void *)password))
		|| !(ret->ec_key = EVP_PKEY_get1_EC_KEY(pkey))) {
		ERR_print_errors_fp(stderr);
		EC_KEYFree(ret);
		ret = NULL;
	}
	EVP_PKEY_free(pkey);
	return ret;
}

int EC_KEYToPEM(EC_KEY *sk, FILE *fp, const char *password)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	if (!sk || !sk->ec_key || !fp) {
		return -1;
	}
	if (!(pkey = EVP_PKEY_new())
		|| !EVP_PKEY_set1_EC_KEY(pkey, sk->ec_key)
		|| !PEM_write_PKCS8PrivateKey(fp, pkey, EVP_sms4_cbc(),
			NULL, 0, 0, (void *)password)) {
		ERR_print_errors_fp(stderr);
		ret = -1;
	}
	EVP_PKEY_free(pkey);
	return ret;
}

void EC_KEYFree(EC_KEY *sk)
{
	if (sk)
		EC_KEY_free(sk->ec_key);
	OPENSSL_free(sk);
}

EC_KEY *EC_KEYExtractPublicKey(EC_KEY *sk)
{
	EC_KEY *ret;
	if (!(ret = OPENSSL_zalloc(sizeof(EC_KEY)))
		|| !(ret->ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))
		|| !EC_KEY_set_public_key(ret->ec_key,
			EC_KEY_get0_public_key(sk->ec_key))) {
		ERR_print_errors_fp(stderr);
		EC_KEYFree(ret);
		ret = NULL;
	}
	return ret;
}

EC_KEY *EC_KEYFromPEM(FILE *fp)
{
	EC_KEY *ret;
	if (!(ret = OPENSSL_zalloc(sizeof(EC_KEY)))
		|| !(ret->ec_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL))) {
		ERR_print_errors_fp(stderr);
		EC_KEYFree(ret);
		ret = NULL;
	}
	return ret;
}

int EC_KEYToPEM(EC_KEY *pk, FILE *fp)
{
	if (!PEM_write_EC_PUBKEY(fp, pk->ec_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

void EC_KEYFree(EC_KEY *pk)
{
	if (pk)
		EC_KEY_free(pk->ec_key);
	OPENSSL_free(pk);
}

int SM2ComputeIDDigest(unsigned char z[32], const char *id, EC_KEY *pk)
{
	size_t len = 32;
	if (!SM2_compute_id_digest(EVP_sm3(), id, strlen(id),
		z, &len, pk->ec_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

int SM2ComputeMessageDigest(unsigned char dgst[32],
	const unsigned char *msg, size_t msglen,
	const char *id, EC_KEY *pk)
{
	size_t dgstlen = 32;
	if (!SM2_compute_message_digest(EVP_sm3(), EVP_sm3(),
		msg, msglen, id, strlen(id),
		dgst, &dgstlen, pk->ec_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

int SM2SignDigest(const unsigned char dgst[32], unsigned char *sig, size_t *siglen, EC_KEY *sk)
{
	unsigned int len = (unsigned int)*siglen;
	if (!SM2_sign(NID_undef, dgst, 32, sig, &len, sk->ec_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	*siglen = len;
	return 0;
}

int SM2VerifyDigest(const unsigned char dgst[32], const unsigned char *sig,
	size_t siglen, EC_KEY *pk)
{

	int r;

	r = SM2_verify(NID_undef, dgst, 32, sig, siglen, pk->ec_key);
	if (r < 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	} else if (r == 0) {
		return -1; /* should we return a special value? */
	}

	return 0;
}

struct SM2Context {
	EVP_MD_CTX *mctx;
	EC_KEY *ec_key;
};

SM2Context *SM2ContextNew(void)
{
	SM2Context *ret;
	if (!(ret = OPENSSL_zalloc(sizeof(SM2Context)))
		|| !(ret->mctx = EVP_MD_CTX_new())) {
		ERR_print_errors_fp(stderr);
		SM2ContextFree(ret);
		return NULL;
	}
	return ret;
}


void SM2ContextFree(SM2Context *ctx)
{
	if (ctx) {
		EVP_MD_CTX_free(ctx->mctx);
		EC_KEY_free(ctx->ec_key);
	}
	OPENSSL_free(ctx);
}

int SM2SignInit(SM2Context *ctx, const char *id, EC_KEY *sk)
{
	unsigned char z[32];
	size_t len = sizeof(z);

	if (ctx->ec_key)
		EC_KEY_free(ctx->ec_key);
	if (!(ctx->ec_key = EC_KEY_dup(sk->ec_key))
		|| !SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &len, ctx->ec_key)
		|| !EVP_DigestInit_ex(ctx->mctx, EVP_sm3(), NULL)
		|| !EVP_DigestUpdate(ctx->mctx, z, 32)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

int SM2SignUpdate(SM2Context *ctx, const void *data, size_t cnt)
{
	if (!EVP_DigestUpdate(ctx->mctx, data, cnt)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

int SM2SignFinal(SM2Context *ctx, unsigned char *sig, size_t *siglen)
{
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int len = sizeof(dgst);

	if (!EVP_DigestFinal_ex(ctx->mctx, dgst, &len)
		|| !SM2_sign(NID_undef, dgst, len, sig, &len, ctx->ec_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	*siglen = len;
	return 0;
}

int SM2VerifyInit(SM2Context *ctx, const char *id, EC_KEY *pk)
{
	unsigned char z[32];
	size_t len = sizeof(z);

	if (ctx->ec_key)
		EC_KEY_free(ctx->ec_key);
	if (!(ctx->ec_key = EC_KEY_dup(pk->ec_key))
		|| !SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &len, ctx->ec_key)
		|| !EVP_DigestInit_ex(ctx->mctx, EVP_sm3(), NULL)
		|| !EVP_DigestUpdate(ctx->mctx, z, 32)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

int SM2VerifyUpdate(SM2Context *ctx, const void *data, size_t cnt)
{
	if (!EVP_DigestUpdate(ctx->mctx, data, cnt)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

int SM2VerifyFinal(SM2Context *ctx, unsigned char *sig, size_t siglen)
{
	int vret;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int len = sizeof(dgst);

	if (!EVP_DigestFinal_ex(ctx->mctx, dgst, &len)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	vret = SM2_verify(NID_undef, dgst, len, sig, siglen, ctx->ec_key);
	if (vret < 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (vret == 0) {
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	EC_KEY *sk = NULL;
	EC_KEY *pk = NULL;
	SM2Context *ctx = NULL;
	unsigned char dgst[32];
	unsigned char sig[80];
	size_t siglen = sizeof(sig);
	size_t i;

	if (!(sk = EC_KEYGenerate())
		|| !(pk = EC_KEYExtractPublicKey(sk))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	printf("sm2 key pair generate\n");

	if (LIBSM_OK != SM2ComputeIDDigest(dgst, "Alice", pk)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	printf("Z = ");
	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");

	if (!(ctx = SM2ContextNew())
		|| LIBSM_OK != SM2SignInit(ctx, "Alice", sk)
		|| LIBSM_OK != SM2SignUpdate(ctx, "message", sizeof("message"))
		|| LIBSM_OK != SM2SignFinal(ctx, sig, &siglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	printf("signature = ");
	for (i = 0; i < siglen; i++) {
		printf("%02x", sig[i]);
	}
	printf("\n");

	if (LIBSM_OK != SM2VerifyInit(ctx, "Alice", pk)
		|| LIBSM_OK != SM2VerifyUpdate(ctx, "message", sizeof("message"))
		|| LIBSM_OK != SM2VerifyFinal(ctx, sig, siglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	printf("verification success!\n");

end:
	EC_KEYFree(sk);
	EC_KEYFree(pk);
	SM2ContextFree(ctx);
	return 0;
}
