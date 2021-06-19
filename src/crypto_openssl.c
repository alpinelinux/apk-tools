#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "apk_crypto.h"

static const char *apk_digest_str[] = {
	[APK_DIGEST_NONE]	= "none",
	[APK_DIGEST_MD5]	= "md5",
	[APK_DIGEST_SHA1]	= "sha1",
	[APK_DIGEST_SHA256]	= "sha256",
	[APK_DIGEST_SHA512]	= "sha512",
};

const char *apk_digest_alg_str(uint8_t alg)
{
	const char *alg_str = "unknown";
	if (alg < ARRAY_SIZE(apk_digest_str))
		alg_str = apk_digest_str[alg];
	return alg_str;
}

int apk_digest_alg_len(uint8_t alg)
{
	switch (alg) {
	case APK_DIGEST_MD5:	return 16;
	case APK_DIGEST_SHA1:	return 20;
	case APK_DIGEST_SHA256:	return 32;
	case APK_DIGEST_SHA512:	return 64;
	default:		return 0;
	}
}

uint8_t apk_digest_alg_by_len(int len)
{
	switch (len) {
	case 0:	 return APK_DIGEST_NONE;
	case 16: return APK_DIGEST_MD5;
	case 20: return APK_DIGEST_SHA1;
	case 32: return APK_DIGEST_SHA256;
	case 64: return APK_DIGEST_SHA512;
	default: return APK_DIGEST_NONE;
	}
}

uint8_t apk_digest_alg_from_csum(int csum)
{
	switch (csum) {
	case APK_CHECKSUM_NONE:		return APK_DIGEST_NONE;
	case APK_CHECKSUM_MD5:		return APK_DIGEST_MD5;
	case APK_CHECKSUM_SHA1:		return APK_DIGEST_SHA1;
	default:			return APK_DIGEST_NONE;
	}
}

uint8_t apk_digest_from_blob(struct apk_digest *d, apk_blob_t b)
{
	d->alg = apk_digest_alg_by_len(b.len);
	d->len = 0;
	if (d->alg != APK_DIGEST_NONE) {
		d->len = b.len;
		memcpy(d->data, b.ptr, d->len);
	}
	return d->alg;
}

int apk_pkey_init(struct apk_pkey *pkey, EVP_PKEY *key)
{
	unsigned char dig[EVP_MAX_MD_SIZE], *pub = NULL;
	unsigned int dlen = sizeof dig;
	int len;

	if ((len = i2d_PublicKey(key, &pub)) < 0) return -EIO;
	EVP_Digest(pub, len, dig, &dlen, EVP_sha512(), NULL);
	memcpy(pkey->id, dig, sizeof pkey->id);
	OPENSSL_free(pub);

	pkey->key = key;
	return 0;
}

void apk_pkey_free(struct apk_pkey *pkey)
{
	EVP_PKEY_free(pkey->key);
}

int apk_pkey_load(struct apk_pkey *pkey, int dirfd, const char *fn)
{
	EVP_PKEY *key;
	BIO *bio;
	int fd;

	fd = openat(dirfd, fn, O_RDONLY|O_CLOEXEC);
	if (fd < 0) return -errno;

	bio = BIO_new_fp(fdopen(fd, "r"), BIO_CLOSE);
	if (!bio) return -ENOMEM;

	key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!key) {
		BIO_reset(bio);
		key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	}
	ERR_clear_error();

	BIO_free(bio);
	if (!key) return -EBADMSG;

	apk_pkey_init(pkey, key);
	return 0;
}

int apk_sign_start(struct apk_digest_ctx *dctx, struct apk_pkey *pkey)
{
	if (EVP_MD_CTX_reset(dctx->mdctx) != 1 ||
	    EVP_DigestSignInit(dctx->mdctx, NULL, EVP_sha512(), NULL, pkey->key) != 1)
		return -EIO;
	return 0;
}

int apk_sign(struct apk_digest_ctx *dctx, void *sig, size_t *len)
{
	if (EVP_DigestSignFinal(dctx->mdctx, sig, len) != 1) {
		ERR_print_errors_fp(stderr);
		return -EBADMSG;
	}
	return 0;
}

int apk_verify_start(struct apk_digest_ctx *dctx, struct apk_pkey *pkey)
{
	if (EVP_MD_CTX_reset(dctx->mdctx) != 1 ||
	    EVP_DigestVerifyInit(dctx->mdctx, NULL, EVP_sha512(), NULL, pkey->key) != 1)
		return -EIO;
	return 0;
}

int apk_verify(struct apk_digest_ctx *dctx, void *sig, size_t len)
{
	if (EVP_DigestVerifyFinal(dctx->mdctx, sig, len) != 1) {
		ERR_print_errors_fp(stderr);
		return -EBADMSG;
	}
	return 0;
}
