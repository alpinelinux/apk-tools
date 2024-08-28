#include "apk_defines.h"
#include "apk_trust.h"
#include "apk_io.h"

struct apk_trust_key *apk_trust_load_key(int dirfd, const char *filename, int priv)
{
	struct apk_trust_key *key;
	int r;

	key = calloc(1, sizeof *key);
	if (!key) return ERR_PTR(-ENOMEM);

	r = apk_pkey_load(&key->key, dirfd, filename, priv);
	if (r) {
		free(key);
		return ERR_PTR(r);
	}

	list_init(&key->key_node);
	key->filename = strdup(filename);
	return key;
}

static int __apk_trust_load_pubkey(void *pctx, int dirfd, const char *filename)
{
	struct apk_trust *trust = pctx;
	struct apk_trust_key *key = apk_trust_load_key(dirfd, filename, 0);

	if (!IS_ERR(key))
		list_add_tail(&key->key_node, &trust->trusted_key_list);

	return 0;
}

void apk_trust_init(struct apk_trust *trust)
{
	*trust = (struct apk_trust){};
	apk_digest_ctx_init(&trust->dctx, APK_DIGEST_NONE);
	list_init(&trust->trusted_key_list);
	list_init(&trust->private_key_list);
}

int apk_trust_load_keys(struct apk_trust *trust, int dirfd)
{
	if (!trust->keys_loaded) {
		trust->keys_loaded = 1;
		apk_dir_foreach_file(dirfd, __apk_trust_load_pubkey, trust);
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
	__apk_trust_free_keys(&trust->trusted_key_list);
	__apk_trust_free_keys(&trust->private_key_list);
	apk_digest_ctx_free(&trust->dctx);
}

struct apk_pkey *apk_trust_key_by_name(struct apk_trust *trust, const char *filename)
{
	struct apk_trust_key *tkey;

	list_for_each_entry(tkey, &trust->trusted_key_list, key_node)
		if (tkey->filename && strcmp(tkey->filename, filename) == 0)
			return &tkey->key;
	return NULL;
}
