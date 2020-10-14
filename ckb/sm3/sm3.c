/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <string.h>
#include<stdio.h>
#include<time.h>
#include "sm3.h"

#define GET32(pc)  (					\
((unsigned int)(pc)[0] << 24) ^ \
((unsigned int)(pc)[1] << 16) ^ \
((unsigned int)(pc)[2] << 8) ^ \
((unsigned int)(pc)[3]))


#define PUT32(st, ct)					\
(ct)[0] = (unsigned char)((st) >> 24);		\
(ct)[1] = (unsigned char)((st) >> 16);		\
(ct)[2] = (unsigned char)((st) >> 8);		\
(ct)[3] = (unsigned char)(st)

#define GETU32(pc)  (					\
	((unsigned int)(pc)[0] << 24) ^ \
	((unsigned int)(pc)[1] << 16) ^ \
	((unsigned int)(pc)[2] << 8) ^ \
	((unsigned int)(pc)[3]))


#define PUTU32(ct, st)					\
	(ct)[0] = (unsigned char)((st) >> 24);		\
	(ct)[1] = (unsigned char)((st) >> 16);		\
	(ct)[2] = (unsigned char)((st) >> 8);		\
	(ct)[3] = (unsigned char)(st)

#define ROL32(x,i)					\
(((x) << i) | ((x) >> (32 - i)))

static void sm3_compress_blocks(uint32_t digest[8], const unsigned char* data, size_t blocks);

void sm3_init(sm3_ctx_t* ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;
}

void sm3_update(sm3_ctx_t* ctx, const unsigned char* data, size_t data_len)
{
	size_t blocks;

	if (ctx->num) 
	{
		size_t left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) 
		{
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		}
		else 
		{
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress_blocks(ctx->digest, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}

	blocks = data_len / SM3_BLOCK_SIZE;
	sm3_compress_blocks(ctx->digest, data, blocks);
	ctx->nblocks += blocks;
	data += SM3_BLOCK_SIZE * blocks;
	data_len -= SM3_BLOCK_SIZE * blocks;

	ctx->num = data_len;
	if (data_len) 
	{
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_final(sm3_ctx_t* ctx, unsigned char* digest)
{
	size_t i;

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE)
	{
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	}
	else
	{
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}
	PUTU32(ctx->block + 56, ctx->nblocks >> 23);
	PUTU32(ctx->block + 60, (ctx->nblocks << 9) + (ctx->num << 3));

	sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < 8; i++) 
	{
		PUTU32(digest + i * 4, ctx->digest[i]);
	}
}

#define ROTL(x,n)  (((x)<<(n)) | ((x)>>(32-(n))))
#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x),17))
#define P1(x) ((x) ^ ROL32((x),15) ^ ROL32((x),23))

#define FF00(x,y,z)  ((x) ^ (y) ^ (z))
#define FF16(x,y,z)  (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z)  ((x) ^ (y) ^ (z))
#define GG16(x,y,z)  ((((y)^(z)) & (x)) ^ (z))

#define R(A, B, C, D, E, F, G, H, xx)				\
	SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);		\
	SS2 = SS1 ^ ROL32(A, 12);				\
	TT1 = FF##xx(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);	\
	TT2 = GG##xx(E, F, G) + H + SS1 + W[j];			\
	B = ROL32(B, 9);					\
	H = TT1;						\
	F = ROL32(F, 19);					\
	D = P0(TT2);						\
	j++

#define R8(A, B, C, D, E, F, G, H, xx)				\
	R(A, B, C, D, E, F, G, H, xx);				\
	R(H, A, B, C, D, E, F, G, xx);				\
	R(G, H, A, B, C, D, E, F, xx);				\
	R(F, G, H, A, B, C, D, E, xx);				\
	R(E, F, G, H, A, B, C, D, xx);				\
	R(D, E, F, G, H, A, B, C, xx);				\
	R(C, D, E, F, G, H, A, B, xx);				\
	R(B, C, D, E, F, G, H, A, xx)



#define T00 0x79cc4519U
#define T16 0x7a879d8aU

#define K0	0x79cc4519U
#define K1	0xf3988a32U
#define K2	0xe7311465U
#define K3	0xce6228cbU
#define K4	0x9cc45197U
#define K5	0x3988a32fU
#define K6	0x7311465eU
#define K7	0xe6228cbcU
#define K8	0xcc451979U
#define K9	0x988a32f3U
#define K10	0x311465e7U
#define K11	0x6228cbceU
#define K12	0xc451979cU
#define K13	0x88a32f39U
#define K14	0x11465e73U
#define K15	0x228cbce6U
#define K16	0x9d8a7a87U
#define K17	0x3b14f50fU
#define K18	0x7629ea1eU
#define K19	0xec53d43cU
#define K20	0xd8a7a879U
#define K21	0xb14f50f3U
#define K22	0x629ea1e7U
#define K23	0xc53d43ceU
#define K24	0x8a7a879dU
#define K25	0x14f50f3bU
#define K26	0x29ea1e76U
#define K27	0x53d43cecU
#define K28	0xa7a879d8U
#define K29	0x4f50f3b1U
#define K30	0x9ea1e762U
#define K31	0x3d43cec5U
#define K32	0x7a879d8aU
#define K33	0xf50f3b14U
#define K34	0xea1e7629U
#define K35	0xd43cec53U
#define K36	0xa879d8a7U
#define K37	0x50f3b14fU
#define K38	0xa1e7629eU
#define K39	0x43cec53dU
#define K40	0x879d8a7aU
#define K41	0x0f3b14f5U
#define K42	0x1e7629eaU
#define K43	0x3cec53d4U
#define K44	0x79d8a7a8U
#define K45	0xf3b14f50U
#define K46	0xe7629ea1U
#define K47	0xcec53d43U
#define K48	0x9d8a7a87U
#define K49	0x3b14f50fU
#define K50	0x7629ea1eU
#define K51	0xec53d43cU
#define K52	0xd8a7a879U
#define K53	0xb14f50f3U
#define K54	0x629ea1e7U
#define K55	0xc53d43ceU
#define K56	0x8a7a879dU
#define K57	0x14f50f3bU
#define K58	0x29ea1e76U
#define K59	0x53d43cecU
#define K60	0xa7a879d8U
#define K61	0x4f50f3b1U
#define K62	0x9ea1e762U
#define K63	0x3d43cec5U

const uint32_t K[64] =
{
	K0,  K1,  K2,  K3,  K4,  K5,  K6,  K7,
	K8,  K9,  K10, K11, K12, K13, K14, K15,
	K16, K17, K18, K19, K20, K21, K22, K23,
	K24, K25, K26, K27, K28, K29, K30, K31,
	K32, K33, K34, K35, K36, K37, K38, K39,
	K40, K41, K42, K43, K44, K45, K46, K47,
	K48, K49, K50, K51, K52, K53, K54, K55,
	K56, K57, K58, K59, K60, K61, K62, K63,
};

static void sm3_compress_blocks(uint32_t digest[8], const unsigned char* data, size_t blocks)
{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t E;
	uint32_t F;
	uint32_t G;
	uint32_t H;
	uint32_t W[68];
	uint32_t SS1, SS2, TT1, TT2;
	size_t j;
	while (blocks--)
	{
		A = digest[0];
		B = digest[1];
		C = digest[2];
		D = digest[3];
		E = digest[4];
		F = digest[5];
		G = digest[6];
		H = digest[7];
		for (j = 0; j < 16; j++)
			W[j] = GETU32(data + j * 4);
		for (; j < 68; j++)
			W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15))
			^ ROL32(W[j - 13], 7) ^ W[j - 6];
		j = 0;
		R8(A, B, C, D, E, F, G, H, 00);
		R8(A, B, C, D, E, F, G, H, 00);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		digest[0] ^= A;
		digest[1] ^= B;
		digest[2] ^= C;
		digest[3] ^= D;
		digest[4] ^= E;
		digest[5] ^= F;
		digest[6] ^= G;
		digest[7] ^= H;
		data += 64;
	}
}

void sm3_compress(uint32_t digest[8], const unsigned char block[64])
{
	sm3_compress_blocks(digest, block, 1);
}

void sm3_string(const unsigned char* msg, size_t msglen, unsigned char dgst[SM3_DIGEST_LENGTH])
{
	sm3_ctx_t ctx;
	sm3_init(&ctx);
	sm3_update(&ctx, msg, msglen);
	sm3_final(&ctx, dgst);
	memset(&ctx, 0, sizeof(sm3_ctx_t));
}


unsigned char Msg[(1<<25)];

void sm3_speed()
{
	unsigned char MsgHash[SM3_DIGEST_LENGTH];
	clock_t t1, t2;
	size_t all_data,len;
	all_data = sizeof(Msg);

	len = (1 << 13);

	for ( len; len > 0; len = len >>1 )
	{
		t1 = clock();
		for (size_t i = 0; i < len; i++)sm3_string(Msg, all_data/len, MsgHash);
		t2 = clock();//
		printf("%10zd times * %10zd Byte costs  ", len, all_data / len);
		printf("%10.3lfs,  speed %10.3lf MB/s\n", ((double)((size_t)t2 - t1)) / (double)CLOCKS_PER_SEC, (((double)(all_data)) / (((double)((size_t)t2 - t1)) / (double)CLOCKS_PER_SEC))/((double)(1<<20)));
	}
}

int sm3_test()
{
	size_t i;
	unsigned char MsgHash[SM3_DIGEST_LENGTH];
	unsigned char MsgHash_test[SM3_DIGEST_LENGTH] = {0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0};
	sm3_string("abc", 3, MsgHash);
	for (i = 0; i < SM3_DIGEST_LENGTH; i++)
	{
		if (MsgHash[i] != MsgHash_test[i])break;
	}
	if (i == SM3_DIGEST_LENGTH)return 1;
	else return 0;
}

void main()
{
	if (sm3_test())
	{
		printf("sm3 test OK\n");
		sm3_speed();
	}
	
}
