#include "apk_crypto.h"

static const char *apk_digest_str[] = {
	[APK_DIGEST_NONE]	= "none",
	[APK_DIGEST_MD5]	= "md5",
	[APK_DIGEST_SHA1]	= "sha1",
	[APK_DIGEST_SHA256_160] = "sha256-160",
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
	case APK_DIGEST_MD5:		return APK_DIGEST_LENGTH_MD5;
	case APK_DIGEST_SHA1:		return APK_DIGEST_LENGTH_SHA1;
	case APK_DIGEST_SHA256_160:	return APK_DIGEST_LENGTH_SHA256_160;
	case APK_DIGEST_SHA256:		return APK_DIGEST_LENGTH_SHA256;
	case APK_DIGEST_SHA512:		return APK_DIGEST_LENGTH_SHA512;
	default:			return 0;
	}
}

uint8_t apk_digest_alg_by_len(int len)
{
	switch (len) {
	case 0:				return APK_DIGEST_NONE;
	case APK_DIGEST_LENGTH_MD5:	return APK_DIGEST_MD5;
	case APK_DIGEST_LENGTH_SHA1:	return APK_DIGEST_SHA1;
	case APK_DIGEST_LENGTH_SHA256:	return APK_DIGEST_SHA256;
	case APK_DIGEST_LENGTH_SHA512:	return APK_DIGEST_SHA512;
	default:			return APK_DIGEST_NONE;
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

void apk_digest_from_checksum(struct apk_digest *d, const struct apk_checksum *c)
{
	apk_digest_set(d, apk_digest_alg_from_csum(c->type));
	memcpy(d->data, c->data, d->len);
}


void apk_checksum_from_digest(struct apk_checksum *csum, const struct apk_digest *d)
{
	if (d->len > sizeof csum->data) {
		csum->type = APK_CHECKSUM_NONE;
	} else {
		csum->type = d->len;
		memcpy(csum->data, d->data, d->len);
	}
}
