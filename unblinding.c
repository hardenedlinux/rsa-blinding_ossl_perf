/*
 * Build: gcc -shared -fPIC -o unblind.so unblinding.c -L/usr/local/ssl/lib64/ -ldl -lcrypto
 *
*/

#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdio.h>

void force_no_blinding (RSA *rsa){
	if (rsa) {
		RSA_set_flags (rsa, RSA_FLAG_NO_BLINDING);
	//	fprintf (stdout, "RSA blinding disabled via LD_PRELOAD!\n");
	}
}

int RSA_generate_key_ex (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb) {
	int (*orig) (RSA*, int, BIGNUM*, BN_GENCB*) = dlsym (RTLD_NEXT, "RSA_generate_key_ex");
	int ret = orig (rsa, bits, e, cb);
	if (ret ==1)
		force_no_blinding (rsa);
	fprintf (stdout, "RSA blinding disabled via LD_PRELOAD (RSA_generate_key_ex)!\n");

	return ret;
}
/* 
 // no performance impact on key generation
int EVP_PKEY_keygen (EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) {
	int (*orig) (EVP_PKEY_CTX*, EVP_PKEY**) = dlsym (RTLD_NEXT, "EVP_PKEY_keygen");
	int ret = orig (ctx, ppkey);

	if (ret ==1 && *ppkey) {
		if (EVP_PKEY_base_id (*ppkey) == EVP_PKEY_RSA) {
			RSA *rsa = EVP_PKEY_get1_RSA(*ppkey);
			force_no_blinding (rsa);
			RSA_free (rsa);
		}
	}
	//fprintf (stdout, "RSA blinding disabled via LD_PRELOAD (EVP_PKEY_keygen)!\n");
	return ret;
}
*/

static unsigned int BLINDING = 1;

void unblind_evp_ctx (EVP_PKEY_CTX *ctx){
	if (!ctx)
		return;

	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey && EVP_PKEY_base_id (pkey) == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA (pkey);
		if (rsa) {
			if (BLINDING)
				RSA_blinding_on (rsa, NULL);
			else
				RSA_blinding_off (rsa);
		}
	}
}

int EVP_PKEY_sign (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen){
	int (*orig) (EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t) = dlsym (RTLD_NEXT, "EVP_PKEY_sign");
	int ret;
	
	unblind_evp_ctx (ctx);
	ret = orig (ctx, sig, siglen, tbs, tbslen);
	//fprintf (stdout, "RSA blinding disabled via LD_PRELOAD! (EVP_PKEY_sign)\n");

	return ret;
}

int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
	int (*orig) (EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t) = dlsym (RTLD_NEXT, "EVP_PKEY_decrypt");
	int ret;

	unblind_evp_ctx (ctx);
	ret = orig (ctx, out, outlen, in, inlen);
	//fprintf (stdout, "RSA blinding disabled via LD_PRELOAD! (EVP_PKEY_decrypt)\n");
	
	return ret;
}
