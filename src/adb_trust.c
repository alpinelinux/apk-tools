#include <errno.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "apk_defines.h"
#include "adb.h"

struct adb_trust_key {
	struct list_head key_node;
	struct adb_pkey key;

};

/* Trust */
int adb_pkey_init(struct adb_pkey *pkey, EVP_PKEY *key)
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

void adb_pkey_free(struct adb_pkey *pkey)
{
	EVP_PKEY_free(pkey->key);
}

int adb_pkey_load(struct adb_pkey *pkey, int dirfd, const char *fn)
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

	adb_pkey_init(pkey, key);
	return 0;
}

static struct adb_trust_key *adb_trust_load_key(int dirfd, const char *filename)
{
	struct adb_trust_key *key;
	int r;

	key = calloc(1, sizeof *key);
	if (!key) return ERR_PTR(-ENOMEM);

	r = adb_pkey_load(&key->key, dirfd, filename);
	if (r) {
		free(key);
		return ERR_PTR(-ENOKEY);
	}

	list_init(&key->key_node);
	return key;
}

static int __adb_trust_load_pubkey(void *pctx, int dirfd, const char *filename)
{
	struct adb_trust *trust = pctx;
	struct adb_trust_key *key = adb_trust_load_key(dirfd, filename);

	if (!IS_ERR(key))
		list_add_tail(&key->key_node, &trust->trusted_key_list);

	return 0;
}

int adb_trust_init(struct adb_trust *trust, int dirfd, struct apk_string_array *pkey_files)
{
	char **fn;

	*trust = (struct adb_trust){
		.mdctx = EVP_MD_CTX_new(),
	};
	if (!trust->mdctx) return -ENOMEM;
	EVP_MD_CTX_set_flags(trust->mdctx, EVP_MD_CTX_FLAG_FINALISE);
	list_init(&trust->trusted_key_list);
	list_init(&trust->private_key_list);
	apk_dir_foreach_file(dirfd, __adb_trust_load_pubkey, trust);

	foreach_array_item(fn, pkey_files) {
		struct adb_trust_key *key = adb_trust_load_key(AT_FDCWD, *fn);
		if (IS_ERR(key)) return PTR_ERR(key);
		list_add_tail(&key->key_node, &trust->private_key_list);
	}

	return 0;
}

static void __adb_trust_free_keys(struct list_head *h)
{
	struct adb_trust_key *tkey, *n;

	list_for_each_entry_safe(tkey, n, h, key_node) {
		list_del(&tkey->key_node);
		adb_pkey_free(&tkey->key);
		free(tkey);
	}
}

void adb_trust_free(struct adb_trust *trust)
{
	if (!trust->mdctx) return;
	__adb_trust_free_keys(&trust->trusted_key_list);
	__adb_trust_free_keys(&trust->private_key_list);
	EVP_MD_CTX_free(trust->mdctx);
}

static int adb_verify_ctx_calc(struct adb_verify_ctx *vfy, unsigned int hash_alg, apk_blob_t data, apk_blob_t *pmd)
{
	const EVP_MD *evp;
	apk_blob_t md;

	switch (hash_alg) {
	case ADB_HASH_SHA512:
		evp = EVP_sha512();
		*pmd = md = APK_BLOB_BUF(vfy->sha512);
		break;
	default:
		return -ENOTSUP;
	}

	if (!(vfy->calc & (1 << hash_alg))) {
		unsigned int sz = md.len;
		if (APK_BLOB_IS_NULL(data)) return -ENOMSG;
		if (EVP_Digest(data.ptr, data.len, (unsigned char*) md.ptr, &sz, evp, NULL) != 1 ||
		    sz != md.len)
			return -EIO;
		vfy->calc |= (1 << hash_alg);
	}
	return 0;
}

int adb_trust_write_signatures(struct adb_trust *trust, struct adb *db, struct adb_verify_ctx *vfy, struct apk_ostream *os)
{
	union {
		struct adb_sign_hdr hdr;
		struct adb_sign_v0 v0;
		unsigned char buf[8192];
	} sig;
	struct adb_trust_key *tkey;
	apk_blob_t md;
	size_t siglen;
	int r;

	if (!vfy) {
		vfy = alloca(sizeof *vfy);
		memset(vfy, 0, sizeof *vfy);
	}

	r = adb_verify_ctx_calc(vfy, ADB_HASH_SHA512, db->adb, &md);
	if (r) return r;

	list_for_each_entry(tkey, &trust->private_key_list, key_node) {
		sig.v0 = (struct adb_sign_v0) {
			.hdr.sign_ver = 0,
			.hdr.hash_alg = ADB_HASH_SHA512,
		};
		memcpy(sig.v0.id, tkey->key.id, sizeof(sig.v0.id));

		siglen = sizeof sig.buf - sizeof sig.v0;
		EVP_MD_CTX_set_pkey_ctx(trust->mdctx, NULL);
		if (EVP_DigestSignInit(trust->mdctx, NULL, EVP_sha512(), NULL, tkey->key.key) != 1 ||
		    EVP_DigestUpdate(trust->mdctx, &db->hdr, sizeof db->hdr) != 1 ||
		    EVP_DigestUpdate(trust->mdctx, &sig.hdr.sign_ver, sizeof sig.hdr.sign_ver) != 1 ||
		    EVP_DigestUpdate(trust->mdctx, &sig.hdr.hash_alg, sizeof sig.hdr.hash_alg) != 1 ||
		    EVP_DigestUpdate(trust->mdctx, md.ptr, md.len) != 1 ||
		    EVP_DigestSignFinal(trust->mdctx, sig.v0.sig, &siglen) != 1) {
			ERR_print_errors_fp(stdout);
			goto err_io;
		}

		r = adb_c_block(os, ADB_BLOCK_SIG, APK_BLOB_PTR_LEN((char*) &sig, sizeof(sig.v0) + siglen));
		if (r < 0) goto err;
	}
	return 0;
err_io:
	r = -EIO;
err:
	apk_ostream_cancel(os, r);
	return r;
}

int adb_trust_verify_signature(struct adb_trust *trust, struct adb *db, struct adb_verify_ctx *vfy, apk_blob_t sigb)
{
	struct adb_trust_key *tkey;
	struct adb_sign_hdr *sig;
	struct adb_sign_v0 *sig0;
	apk_blob_t md;

	if (APK_BLOB_IS_NULL(db->adb)) return -ENOMSG;
	if (sigb.len < sizeof(struct adb_sign_hdr)) return -EBADMSG;

	sig  = (struct adb_sign_hdr *) sigb.ptr;
	sig0 = (struct adb_sign_v0 *) sigb.ptr;
	if (sig->sign_ver != 0) return -ENOSYS;

	list_for_each_entry(tkey, &trust->trusted_key_list, key_node) {
		if (memcmp(sig0->id, tkey->key.id, sizeof sig0->id) != 0) continue;
		if (adb_verify_ctx_calc(vfy, sig->hash_alg, db->adb, &md) != 0) continue;

		EVP_MD_CTX_set_pkey_ctx(trust->mdctx, NULL);
		if (EVP_DigestVerifyInit(trust->mdctx, NULL, EVP_sha512(), NULL, tkey->key.key) != 1 ||
		    EVP_DigestUpdate(trust->mdctx, &db->hdr, sizeof db->hdr) != 1 ||
		    EVP_DigestUpdate(trust->mdctx, &sig->sign_ver, sizeof sig->sign_ver) != 1 ||
		    EVP_DigestUpdate(trust->mdctx, &sig->hash_alg, sizeof sig->hash_alg) != 1 ||
		    EVP_DigestUpdate(trust->mdctx, md.ptr, md.len) != 1 ||
		    EVP_DigestVerifyFinal(trust->mdctx, sig0->sig, sigb.len - sizeof(*sig0)) != 1) {
			ERR_clear_error();
			continue;
		}

		return 0;
	}

	return -EKEYREJECTED;
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
