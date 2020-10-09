#include <errno.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "apk_defines.h"
#include "apk_trust.h"
#include "apk_io.h"

/* Trust */
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

static struct apk_trust_key *apk_trust_load_key(int dirfd, const char *filename)
{
	struct apk_trust_key *key;
	int r;

	key = calloc(1, sizeof *key);
	if (!key) return ERR_PTR(-ENOMEM);

	r = apk_pkey_load(&key->key, dirfd, filename);
	if (r) {
		free(key);
		return ERR_PTR(-ENOKEY);
	}

	list_init(&key->key_node);
	key->filename = strdup(filename);
	return key;
}

static int __apk_trust_load_pubkey(void *pctx, int dirfd, const char *filename)
{
	struct apk_trust *trust = pctx;
	struct apk_trust_key *key = apk_trust_load_key(dirfd, filename);

	if (!IS_ERR(key))
		list_add_tail(&key->key_node, &trust->trusted_key_list);

	return 0;
}

int apk_trust_init(struct apk_trust *trust, int dirfd, struct apk_string_array *pkey_files)
{
	char **fn;

	*trust = (struct apk_trust){
		.mdctx = EVP_MD_CTX_new(),
	};
	if (!trust->mdctx) return -ENOMEM;
	EVP_MD_CTX_set_flags(trust->mdctx, EVP_MD_CTX_FLAG_FINALISE);
	list_init(&trust->trusted_key_list);
	list_init(&trust->private_key_list);
	apk_dir_foreach_file(dirfd, __apk_trust_load_pubkey, trust);

	foreach_array_item(fn, pkey_files) {
		struct apk_trust_key *key = apk_trust_load_key(AT_FDCWD, *fn);
		if (IS_ERR(key)) return PTR_ERR(key);
		list_add_tail(&key->key_node, &trust->private_key_list);
	}

	return 0;
}

static void __apk_trust_free_keys(struct list_head *h)
{
	struct apk_trust_key *tkey, *n;

	list_for_each_entry_safe(tkey, n, h, key_node) {
		list_del(&tkey->key_node);
		apk_pkey_free(&tkey->key);
		free(tkey->filename);
		free(tkey);
	}
}

void apk_trust_free(struct apk_trust *trust)
{
	if (!trust->mdctx) return;
	__apk_trust_free_keys(&trust->trusted_key_list);
	__apk_trust_free_keys(&trust->private_key_list);
	EVP_MD_CTX_free(trust->mdctx);
}

struct apk_pkey *apk_trust_key_by_name(struct apk_trust *trust, const char *filename)
{
	struct apk_trust_key *tkey;

	list_for_each_entry(tkey, &trust->trusted_key_list, key_node)
		if (tkey->filename && strcmp(tkey->filename, filename) == 0)
			return &tkey->key;
	return NULL;
}


/* Command group for signing */

#include "apk_applet.h"

#define SIGNING_OPTIONS(OPT) \
	OPT(OPT_SIGN_sign_key,		APK_OPT_ARG "sign-key")

APK_OPT_GROUP(options_signing, "Signing", SIGNING_OPTIONS);

static int option_parse_signing(void *ctx, struct apk_ctx *ac, int optch, const char *optarg)
{
	switch (optch) {
	case OPT_SIGN_sign_key:
		*apk_string_array_add(&ac->private_keys) = (char*) optarg;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

const struct apk_option_group optgroup_signing = {
	.desc = options_signing,
	.parse = option_parse_signing,
};
