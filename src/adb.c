#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "adb.h"
#include "apk_blob.h"
#include "apk_trust.h"

static char padding_zeroes[ADB_BLOCK_ALIGNMENT] = {0};

/* Block enumeration */
static inline struct adb_block *adb_block_validate(struct adb_block *blk, apk_blob_t b)
{
	size_t pos = (char *)blk - b.ptr;
	if (pos == b.len) return NULL;
	if (sizeof(struct adb_block) > b.len - pos) return ERR_PTR(-APKE_ADB_BLOCK);
	if (adb_block_rawsize(blk) < sizeof(struct adb_block)) return ERR_PTR(-APKE_ADB_BLOCK);
	if (adb_block_size(blk) > b.len - pos) return ERR_PTR(-APKE_ADB_BLOCK);
	return blk;
}

static struct adb_block *adb_block_first(apk_blob_t b)
{
	return adb_block_validate((struct adb_block*)b.ptr, b);
}

static struct adb_block *adb_block_next(struct adb_block *cur, apk_blob_t b)
{
	return adb_block_validate((struct adb_block*)((char*)cur + adb_block_size(cur)), b);
}

#define adb_foreach_block(__blk, __adb) \
	for (__blk = adb_block_first(__adb); __blk && !IS_ERR(__blk); __blk = adb_block_next(__blk, __adb))

/* Init stuff */
int adb_free(struct adb *db)
{
	if (db->is) {
		// read-only adb
		apk_istream_close(db->is);
	} else {
		// writable adb
		struct adb_w_bucket *bucket, *nxt;
		int i;
		for (i = 0; i < db->num_buckets; i++)
			list_for_each_entry_safe(bucket, nxt, &db->bucket[i], node)
				free(bucket);
		free(db->adb.ptr);
	}
	memset(db, 0, sizeof *db);
	return 0;
}

void adb_reset(struct adb *db)
{
	struct adb_w_bucket *bucket, *nxt;
	int i;

	for (i = 0; i < db->num_buckets; i++) {
		list_for_each_entry_safe(bucket, nxt, &db->bucket[i], node)
			free(bucket);
		list_init(&db->bucket[i]);
	}
	db->adb.len = sizeof(struct adb_hdr);
}

static int __adb_dummy_cb(struct adb *db, struct adb_block *b, struct apk_istream *is)
{
	return 0;
}

static int __adb_m_parse(struct adb *db, apk_blob_t data, struct apk_trust *t,
	int (*cb)(struct adb *, struct adb_block *, struct apk_istream *))
{
	struct adb_verify_ctx vfy = {};
	struct adb_block *blk;
	struct apk_istream is;
	int r = 0, trusted = (t && t->allow_untrusted) ? 1 : 0;
	uint32_t type, allowed = BIT(ADB_BLOCK_ADB);

	adb_foreach_block(blk, data) {
		apk_blob_t b = adb_block_blob(blk);
		type = adb_block_type(blk);
		if (!(BIT(type) & allowed)) {
			r = -APKE_ADB_BLOCK;
			break;
		}
		switch (type) {
		case ADB_BLOCK_ADB:
			allowed = BIT(ADB_BLOCK_SIG) | BIT(ADB_BLOCK_DATA) | BIT(ADB_BLOCK_DATAX);
			if (b.len < 16) {
				r = -APKE_ADB_BLOCK;
				goto err;
			}
			if (((struct adb_hdr*)b.ptr)->adb_compat_ver != 0) {
				r = -APKE_ADB_VERSION;
				goto err;
			}
			db->adb = b;
			break;
		case ADB_BLOCK_SIG:
			if (!trusted &&
			    adb_trust_verify_signature(t, db, &vfy, b) == 0)
				trusted = 1;
			break;
		case ADB_BLOCK_DATA:
			allowed = BIT(ADB_BLOCK_DATA) | BIT(ADB_BLOCK_DATAX);
			if (!trusted) {
				r = -APKE_SIGNATURE_UNTRUSTED;
				goto err;
			}
			break;
		case ADB_BLOCK_DATAX:
			r = -APKE_ADB_BLOCK;
			goto err;
		}
		r = cb(db, blk, apk_istream_from_blob(&is, b));
		if (r < 0) break;
	}
err:
	if (r > 0) r = -APKE_ADB_BLOCK;
	if (r == 0) {
		if (IS_ERR(blk)) r = PTR_ERR(blk);
		else if (!trusted) r = -APKE_SIGNATURE_UNTRUSTED;
		else if (!db->adb.ptr) r = -APKE_ADB_BLOCK;
	}
	if (r != 0) db->adb = APK_BLOB_NULL;
	return r;
}

int adb_m_blob(struct adb *db, apk_blob_t blob, struct apk_trust *t)
{
	adb_init(db);
	return __adb_m_parse(db, blob, t, __adb_dummy_cb);
}

static int __adb_m_mmap(struct adb *db, apk_blob_t mmap, uint32_t expected_schema, struct apk_trust *t,
	int (*cb)(struct adb *, struct adb_block *, struct apk_istream *))
{
	struct adb_file_header *hdr;
	int r = -APKE_ADB_HEADER;
	apk_blob_t data = mmap;

	if (!(expected_schema & ADB_SCHEMA_IMPLIED)) {
		if (mmap.len < sizeof *hdr) return -APKE_ADB_HEADER;
		hdr = (struct adb_file_header *) mmap.ptr;
		if (hdr->magic != htole32(ADB_FORMAT_MAGIC)) return -APKE_ADB_HEADER;
		if (expected_schema && expected_schema != le32toh(hdr->schema)) return -APKE_ADB_SCHEMA;
		db->schema = le32toh(hdr->schema);
		data = APK_BLOB_PTR_LEN(mmap.ptr + sizeof *hdr, mmap.len - sizeof *hdr);
	}

	r = __adb_m_parse(db, data, t, cb);
	if (r) goto err;
	return 0;
err:
	adb_free(db);
	return r;
}

static int __adb_m_stream(struct adb *db, struct apk_istream *is, uint32_t expected_schema,
	struct apk_trust *t, int (*cb)(struct adb *, struct adb_block *, struct apk_istream *))
{
	struct adb_file_header hdr;
	struct adb_verify_ctx vfy = {};
	struct adb_block blk;
	struct apk_segment_istream seg;
	void *sig;
	int r = 0, trusted = (t && t->allow_untrusted) ? 1 : 0;
	uint32_t type, allowed = BIT(ADB_BLOCK_ADB);
	size_t sz;

	if (IS_ERR(is)) return PTR_ERR(is);

	if (!(expected_schema & ADB_SCHEMA_IMPLIED)) {
		if ((r = apk_istream_read(is, &hdr, sizeof hdr)) < 0) goto err;
		if (hdr.magic != htole32(ADB_FORMAT_MAGIC)) {
			r = -APKE_ADB_HEADER;
			goto err;
		}
		if (expected_schema && expected_schema != le32toh(hdr.schema)) {
			r = -APKE_ADB_SCHEMA;
			goto err;
		}
		db->schema = le32toh(hdr.schema);
	}

	do {
		r = apk_istream_read_max(is, &blk, sizeof blk);
		if (r != sizeof blk) break;

		type = adb_block_type(&blk);
		if (!(BIT(type) & allowed)) {
			r = -APKE_ADB_BLOCK;
			break;
		}

		sz = adb_block_length(&blk);
		switch (type) {
		case ADB_BLOCK_ADB:
			allowed = BIT(ADB_BLOCK_SIG) | BIT(ADB_BLOCK_DATA) | BIT(ADB_BLOCK_DATAX);
			db->adb.ptr = malloc(sz);
			db->adb.len = sz;
			if (db->adb.len < 16) {
				r = -APKE_ADB_BLOCK;
				goto err;
			}
			if ((r = apk_istream_read(is, db->adb.ptr, sz)) < 0) goto err;
			if (((struct adb_hdr*)db->adb.ptr)->adb_compat_ver != 0) {
				r = -APKE_ADB_VERSION;
				goto err;
			}
			r = cb(db, &blk, apk_istream_from_blob(&seg.is, db->adb));
			if (r < 0) goto err;
			goto skip_padding;
		case ADB_BLOCK_SIG:
			sig = apk_istream_peek(is, sz);
			if (IS_ERR(sig)) {
				r = PTR_ERR(sig);
				goto err;
			}
			if (!trusted &&
			    adb_trust_verify_signature(t, db, &vfy, APK_BLOB_PTR_LEN(sig, sz)) == 0)
				trusted = 1;
			break;
		case ADB_BLOCK_DATA:
			allowed = BIT(ADB_BLOCK_DATA) | BIT(ADB_BLOCK_DATAX);
			if (!trusted) {
				r = -APKE_SIGNATURE_UNTRUSTED;
				goto err;
			}
			break;
		case ADB_BLOCK_DATAX:
			r = -APKE_ADB_BLOCK;
			goto err;
		}

		apk_istream_segment(&seg, is, sz, 0);
		r = cb(db, &blk, &seg.is);
		r = apk_istream_close_error(&seg.is, r);
		if (r < 0) break;

	skip_padding:
		r = apk_istream_read(is, 0, adb_block_padding(&blk));
		if (r < 0) break;
	} while (1);
err:
	if (r > 0) r = -APKE_ADB_BLOCK;
	if (r == 0 || r == -ECANCELED) {
		if (!trusted) r = -APKE_SIGNATURE_UNTRUSTED;
		else if (!db->adb.ptr) r = -APKE_ADB_BLOCK;
	}
	if (r != 0 && r != -ECANCELED) {
		free(db->adb.ptr);
		db->adb = APK_BLOB_NULL;
	}
	return apk_istream_close_error(is, r);
}

int adb_m_process(struct adb *db, struct apk_istream *is, uint32_t expected_schema,
	struct apk_trust *t, int (*cb)(struct adb *, struct adb_block *, struct apk_istream *))
{
	apk_blob_t mmap;

	if (IS_ERR(is)) return PTR_ERR(is);
	mmap = apk_istream_mmap(is);
	memset(db, 0, sizeof *db);
	if (expected_schema & ADB_SCHEMA_IMPLIED)
		db->schema = expected_schema & ~ADB_SCHEMA_IMPLIED;
	if (!cb) cb = __adb_dummy_cb;
	if (!APK_BLOB_IS_NULL(mmap)) {
		db->is = is;
		return __adb_m_mmap(db, mmap, expected_schema, t, cb);
	}
	return __adb_m_stream(db, is, expected_schema, t, cb);
}

static size_t adb_w_raw(struct adb *db, struct iovec *vec, size_t n, size_t len, size_t alignment)
{
	void *ptr;
	size_t offs, i;

	if ((i = ROUND_UP(db->adb.len, alignment) - db->adb.len) != 0) {
		memset(&db->adb.ptr[db->adb.len], 0, i);
		db->adb.len += i;
	}

	if (db->adb.len + len > db->alloc_len) {
		assert(db->num_buckets);
		if (!db->alloc_len) db->alloc_len = 8192;
		while (db->adb.len + len > db->alloc_len)
			db->alloc_len *= 2;
		ptr = realloc(db->adb.ptr, db->alloc_len);
		assert(ptr);
		db->adb.ptr = ptr;
	}

	offs = db->adb.len;
	for (i = 0; i < n; i++) {
		memcpy(&db->adb.ptr[db->adb.len], vec[i].iov_base, vec[i].iov_len);
		db->adb.len += vec[i].iov_len;
	}

	return offs;
}


int adb_w_init_dynamic(struct adb *db, uint32_t schema, void *buckets, size_t num_buckets)
{
	struct adb_hdr hdr = { .adb_compat_ver = 0, .adb_ver = 0 };
	struct iovec vec = { .iov_base = &hdr, .iov_len = sizeof hdr };
	size_t i;

	*db = (struct adb) {
		.schema = schema,
		.num_buckets = num_buckets,
		.bucket = buckets,
	};

	if (num_buckets) {
		for (i = 0; i < db->num_buckets; i++)
			list_init(&db->bucket[i]);
	}

	adb_w_raw(db, &vec, 1, vec.iov_len, sizeof hdr);
	return 0;
}

int adb_w_init_static(struct adb *db, void *buf, size_t bufsz)
{
	*db = (struct adb) {
		.adb.ptr = buf,
		.alloc_len = bufsz,
	};
	return 0;
}

/* Read interface */
static inline void *adb_r_deref(const struct adb *db, adb_val_t v, size_t offs, size_t s)
{
	offs += ADB_VAL_VALUE(v);
	if (offs + s > db->adb.len) return NULL;
	return db->adb.ptr + offs;
}

adb_val_t adb_r_root(const struct adb *db)
{
	if (db->adb.len < sizeof(struct adb_hdr)) return ADB_NULL;
	return ((struct adb_hdr*)db->adb.ptr)->root;
}

uint32_t adb_r_int(const struct adb *db, adb_val_t v)
{
	uint32_t *int4;

	switch (ADB_VAL_TYPE(v)) {
	case ADB_TYPE_INT:
		return ADB_VAL_VALUE(v);
	case ADB_TYPE_INT_32:
		int4 = adb_r_deref(db, v, 0, sizeof int4);
		if (!int4) return 0;
		return le32toh(*int4);
	default:
		return 0;
	}
}

apk_blob_t adb_r_blob(const struct adb *db, adb_val_t v)
{
	void *blob;
	size_t len;

	switch (ADB_VAL_TYPE(v)) {
	case ADB_TYPE_BLOB_8:
		blob = adb_r_deref(db, v, 0, 1);
		len = *(uint8_t*) blob;
		return APK_BLOB_PTR_LEN(adb_r_deref(db, v, 1, len), len);
	case ADB_TYPE_BLOB_16:
		blob = adb_r_deref(db, v, 0, 2);
		len = le16toh(*(uint16_t*) blob);
		return APK_BLOB_PTR_LEN(adb_r_deref(db, v, 2, len), len);
	case ADB_TYPE_BLOB_32:
		blob = adb_r_deref(db, v, 0, 4);
		len = le32toh(*(uint32_t*) blob);
		return APK_BLOB_PTR_LEN(adb_r_deref(db, v, 4, len), len);
	default:
		return APK_BLOB_NULL;
	}
}

struct adb_obj *adb_r_obj(struct adb *db, adb_val_t v, struct adb_obj *obj, const struct adb_object_schema *schema)
{
	adb_val_t *o;
	uint32_t num;

	if (ADB_VAL_TYPE(v) != ADB_TYPE_ARRAY &&
	    ADB_VAL_TYPE(v) != ADB_TYPE_OBJECT)
		goto err;

	o = adb_r_deref(db, v, 0, sizeof(adb_val_t[ADBI_NUM_ENTRIES]));
	if (!o) goto err;

	num = le32toh(o[ADBI_NUM_ENTRIES]);
	o = adb_r_deref(db, v, 0, sizeof(adb_val_t[num]));
	if (!o) goto err;

	*obj = (struct adb_obj) {
		.schema = schema,
		.db = db,
		.num = num,
		.obj = o,
	};
	return obj;
err:
	*obj = (struct adb_obj) {
		.schema = schema,
		.db = db,
		.num = 1,
		.obj = 0,
	};
	return obj;
}

struct adb_obj *adb_r_rootobj(struct adb *db, struct adb_obj *obj, const struct adb_object_schema *schema)
{
	return adb_r_obj(db, adb_r_root(db), obj, schema);
}

const uint8_t *adb_ro_kind(const struct adb_obj *o, unsigned i)
{
	if (o->schema->kind == ADB_KIND_ADB ||
	    o->schema->kind == ADB_KIND_ARRAY)
		i = 1;
	return o->schema->fields[i-1].kind;
}

adb_val_t adb_ro_val(const struct adb_obj *o, unsigned i)
{
	if (i >= o->num) return ADB_NULL;
	return o->obj[i];
}

uint32_t adb_ro_int(const struct adb_obj *o, unsigned i)
{
	return adb_r_int(o->db, adb_ro_val(o, i));
}

apk_blob_t adb_ro_blob(const struct adb_obj *o, unsigned i)
{
	return adb_r_blob(o->db, adb_ro_val(o, i));
}

struct adb_obj *adb_ro_obj(const struct adb_obj *o, unsigned i, struct adb_obj *no)
{
	const struct adb_object_schema *schema = NULL;

	if (o->schema) {
		if (o->schema->kind == ADB_KIND_ARRAY)
			schema = container_of(o->schema->fields[0].kind, struct adb_object_schema, kind);
		else if (i > 0 && i < o->schema->num_fields)
			schema = container_of(o->schema->fields[i-1].kind, struct adb_object_schema, kind);
		assert(schema && (schema->kind == ADB_KIND_OBJECT || schema->kind == ADB_KIND_ARRAY));
	}

	return adb_r_obj(o->db, adb_ro_val(o, i), no, schema);
}

int adb_ro_cmp(const struct adb_obj *o1, const struct adb_obj *o2, unsigned i)
{
	assert(o1->schema->kind == ADB_KIND_OBJECT);
	assert(o1->schema == o2->schema);
	assert(i > 0 && i < o1->schema->num_fields);

	switch (*o1->schema->fields[i-1].kind) {
	case ADB_KIND_BLOB:
	case ADB_KIND_INT:
		return container_of(o1->schema->fields[i-1].kind, struct adb_scalar_schema, kind)->compare(
			o1->db, adb_ro_val(o1, i),
			o2->db, adb_ro_val(o2, i));
	case ADB_KIND_OBJECT: {
		struct adb_obj so1, so2;
		adb_ro_obj(o1, i, &so1);
		adb_ro_obj(o2, i, &so2);
		return so1.schema->compare(&so1, &so2);
		}
	}
	assert(0);
}

static struct adb *__db1, *__db2;
static const struct adb_object_schema *__schema;

static int wacmp(const void *p1, const void *p2)
{
	struct adb_obj o1, o2;
	adb_r_obj(__db1, *(adb_val_t *)p1, &o1, __schema);
	adb_r_obj(__db2, *(adb_val_t *)p2, &o2, __schema);
	return o1.schema->compare(&o1, &o2);
}

static int wadbcmp(const void *p1, const void *p2)
{
	struct adb a1, a2;
	struct adb_obj o1, o2;
	adb_m_blob(&a1, adb_r_blob(__db1, *(adb_val_t *)p1), 0);
	adb_m_blob(&a2, adb_r_blob(__db2, *(adb_val_t *)p2), 0);
	adb_r_rootobj(&a1, &o1, __schema);
	adb_r_rootobj(&a2, &o2, __schema);
	return __schema->compare(&o1, &o2);
}

int adb_ra_find(struct adb_obj *arr, int cur, struct adb *db, adb_val_t val)
{
	adb_val_t *ndx;

	__db1 = db;
	__db2 = arr->db;
	__schema = arr->schema;
	assert(__schema->kind == ADB_KIND_ARRAY);
	__schema = container_of(__schema->fields[0].kind, struct adb_object_schema, kind);

	if (cur == 0) {
		ndx = bsearch(&val, &arr->obj[ADBI_FIRST], adb_ra_num(arr), sizeof(arr->obj[0]), wacmp);
		if (!ndx) return -1;
		cur = ndx - arr->obj;
		while (cur > 1 && wacmp(&val, &arr->obj[cur-1]) == 0) cur--;
	} else {
		cur++;
		if (wacmp(&val, &arr->obj[cur]) != 0)
			return -1;
	}
	return cur;

}

/* Write interface */
static inline size_t iovec_len(struct iovec *vec, size_t nvec)
{
	size_t i, l = 0;
	for (i = 0; i < nvec; i++) l += vec[i].iov_len;
	return l;
}

static unsigned iovec_hash(struct iovec *vec, size_t nvec, size_t *len)
{
	size_t i, l = 0;
	unsigned hash = 5381;

	for (i = 0; i < nvec; i++) {
		hash = apk_blob_hash_seed(APK_BLOB_PTR_LEN(vec[i].iov_base, vec[i].iov_len), hash);
		l += vec[i].iov_len;
	}
	*len = l;
	return hash;
}

static unsigned iovec_memcmp(struct iovec *vec, size_t nvec, void *base)
{
	uint8_t *b = (uint8_t *) base;
	size_t i;

	for (i = 0; i < nvec; i++) {
		if (memcmp(b, vec[i].iov_base, vec[i].iov_len) != 0)
			return 1;
		b += vec[i].iov_len;
	}
	return 0;
}

static adb_val_t adb_w_error(struct adb *db, int rc)
{
	assert(0);
	db->schema = 0;
	return ADB_ERROR(rc);
}

static size_t adb_w_data(struct adb *db, struct iovec *vec, size_t nvec, size_t alignment)
{
	size_t len, i;
	unsigned hash, bucketno;
	struct adb_w_bucket *bucket;
	struct adb_w_bucket_entry *entry = 0;

	if (!db->num_buckets) return adb_w_raw(db, vec, nvec, iovec_len(vec, nvec), alignment);

	hash = iovec_hash(vec, nvec, &len);
	bucketno = hash % db->num_buckets;
	list_for_each_entry(bucket, &db->bucket[bucketno], node) {
		for (i = 0, entry = bucket->entries; i < ARRAY_SIZE(bucket->entries); i++, entry++) {
			if (entry->len == 0) goto add;
			if (entry->hash != hash) continue;
			if (entry->len == len && iovec_memcmp(vec, nvec, &((uint8_t*)db->adb.ptr)[entry->offs]) == 0) {
				if ((entry->offs & alignment) != 0) goto add;
				return entry->offs;
			}
		}
		entry = 0;
	}

	bucket = calloc(1, sizeof *bucket);
	list_init(&bucket->node);
	list_add_tail(&bucket->node, &db->bucket[bucketno]);
	entry = &bucket->entries[0];

add:
	entry->hash = hash;
	entry->len = len;
	entry->offs = adb_w_raw(db, vec, nvec, len, alignment);
	return entry->offs;
}

static size_t adb_w_data1(struct adb *db, void *ptr, size_t len, size_t alignment)
{
	struct iovec vec[] = {
		{ .iov_base = ptr, .iov_len = len },
	};
	if (!ptr) return ADB_NULL;
	return adb_w_data(db, vec, ARRAY_SIZE(vec), alignment);
}

void adb_w_root(struct adb *db, adb_val_t root_val)
{
	if (db->adb.len < sizeof(struct adb_hdr)) {
		adb_w_error(db, APKE_ADB_HEADER);
		return;
	}
	((struct adb_hdr*)db->adb.ptr)->root = root_val;
}

void adb_w_rootobj(struct adb_obj *obj)
{
	adb_w_root(obj->db, adb_w_obj(obj));
}

adb_val_t adb_w_blob(struct adb *db, apk_blob_t b)
{
	union {
		uint32_t u32;
		uint16_t u16;
		uint8_t u8;
	} val;
	uint32_t n = b.len;
	struct iovec vec[2] = {
		{ .iov_base = &val,		.iov_len = sizeof val },
		{ .iov_base = (void *) b.ptr,	.iov_len = n },
	};
	adb_val_t o;

	if (n > 0xffff) {
		val.u32 = htole32(n);
		vec[0].iov_len = sizeof val.u32;
		o = ADB_TYPE_BLOB_32;
	} else if (n > 0xff) {
		val.u16 = htole16(n);
		vec[0].iov_len = sizeof val.u16;
		o = ADB_TYPE_BLOB_16;
	} else if (n > 0) {
		val.u8 = n;
		vec[0].iov_len = sizeof val.u8;
		o = ADB_TYPE_BLOB_8;
	} else {
		return ADB_VAL_NULL;
	}

	return ADB_VAL(o, adb_w_data(db, vec, ARRAY_SIZE(vec), vec[0].iov_len));
}

static adb_val_t adb_w_blob_raw(struct adb *db, apk_blob_t b)
{
	adb_val_t val;
	size_t num_buckets;

	num_buckets = db->num_buckets;
	db->num_buckets = 0;
	val = adb_w_blob(db, b);
	db->num_buckets = num_buckets;
	return val;
}

adb_val_t adb_w_int(struct adb *db, uint32_t val)
{
	if (val >= 0x10000000)
		return ADB_VAL(ADB_TYPE_INT_32, adb_w_data1(db, &val, sizeof val, sizeof val));
	return ADB_VAL(ADB_TYPE_INT, val);
}

adb_val_t adb_w_copy(struct adb *db, struct adb *srcdb, adb_val_t v)
{
	void *ptr;
	size_t sz, align = 1;

	if (db == srcdb) return v;

	switch (ADB_VAL_TYPE(v)) {
	case ADB_TYPE_SPECIAL:
	case ADB_TYPE_INT:
		return v;
	case ADB_TYPE_INT_32:
		sz = align = sizeof(uint32_t);
		goto copy;
	case ADB_TYPE_BLOB_8:
		ptr = adb_r_deref(srcdb, v, 0, 1);
		sz = 1UL + *(uint8_t*) ptr;
		goto copy;
	case ADB_TYPE_BLOB_16:
		ptr = adb_r_deref(srcdb, v, 0, 2);
		sz = 1UL + *(uint16_t*) ptr;
		goto copy;
	case ADB_TYPE_OBJECT:
	case ADB_TYPE_ARRAY: {
		adb_val_t cpy[512];
		struct adb_obj obj;
		adb_r_obj(srcdb, v, &obj, NULL);
		sz = adb_ro_num(&obj);
		if (sz > ARRAY_SIZE(cpy)) return adb_w_error(db, E2BIG);
		cpy[ADBI_NUM_ENTRIES] = obj.obj[ADBI_NUM_ENTRIES];
		for (int i = ADBI_FIRST; i < sz; i++) cpy[i] = adb_w_copy(db, srcdb, adb_ro_val(&obj, i));
		return ADB_VAL(ADB_VAL_TYPE(v), adb_w_data1(db, cpy, sizeof(adb_val_t[sz]), sizeof(adb_val_t)));
	}
	case ADB_TYPE_INT_64:
	case ADB_TYPE_BLOB_32:
	default:
		return adb_w_error(db, ENOSYS);
	}
copy:
	ptr = adb_r_deref(srcdb, v, 0, sz);
	return ADB_VAL(ADB_VAL_TYPE(v), adb_w_data1(db, ptr, sz, align));
}

adb_val_t adb_w_adb(struct adb *db, struct adb *valdb)
{
	uint32_t bsz;
	struct adb_block blk = adb_block_init(ADB_BLOCK_ADB, valdb->adb.len);
	struct iovec vec[] = {
		{ .iov_base = &bsz, .iov_len = sizeof bsz },
		{ .iov_base = &blk, .iov_len = sizeof blk },
		{ .iov_base = valdb->adb.ptr, .iov_len = valdb->adb.len },
		{ .iov_base = padding_zeroes, .iov_len = adb_block_padding(&blk) },
	};
	if (valdb->adb.len <= sizeof(struct adb_hdr)) return ADB_NULL;
	bsz = htole32(iovec_len(vec, ARRAY_SIZE(vec)) - sizeof bsz);
	return ADB_VAL(ADB_TYPE_BLOB_32, adb_w_raw(db, vec, ARRAY_SIZE(vec), iovec_len(vec, ARRAY_SIZE(vec)), sizeof(uint32_t)));
}

adb_val_t adb_w_fromstring(struct adb *db, const uint8_t *kind, apk_blob_t val)
{
	int r;

	switch (*kind) {
	case ADB_KIND_BLOB:
	case ADB_KIND_INT:
		return container_of(kind, struct adb_scalar_schema, kind)->fromstring(db, val);
	case ADB_KIND_OBJECT:
	case ADB_KIND_ARRAY:; {
		struct adb_obj obj;
		struct adb_object_schema *schema = container_of(kind, struct adb_object_schema, kind);
		adb_wo_alloca(&obj, schema, db);
		if (!schema->fromstring) return ADB_ERROR(APKE_ADB_NO_FROMSTRING);
		r = schema->fromstring(&obj, val);
		if (r) return ADB_ERROR(r);
		return adb_w_obj(&obj);
		}
	default:
		return ADB_ERROR(APKE_ADB_NO_FROMSTRING);
	}
}

struct adb_obj *adb_wo_init(struct adb_obj *o, adb_val_t *p, const struct adb_object_schema *schema, struct adb *db)
{
	memset(p, 0, sizeof(adb_val_t[schema->num_fields]));
	/* Use the backing num entries index as the 'maximum' allocated space
	 * information while building the object/array. */
	p[ADBI_NUM_ENTRIES] = schema->num_fields;

	*o = (struct adb_obj) {
		.schema = schema,
		.db = db,
		.obj = p,
		.num = 1,
	};
	return o;
}

struct adb_obj *adb_wo_init_val(struct adb_obj *o, adb_val_t *p, const struct adb_obj *parent, unsigned i)
{
	const uint8_t *kind = adb_ro_kind(parent, i);
	const struct adb_object_schema *schema = 0;
	switch (*kind) {
	case ADB_KIND_OBJECT:
	case ADB_KIND_ARRAY:
		schema = container_of(kind, struct adb_object_schema, kind);
		break;
	case ADB_KIND_ADB:
		schema = container_of(kind, struct adb_adb_schema, kind)->schema;
		break;
	default:
		assert(1);
	}

	return adb_wo_init(o, p, schema, parent->db);
}

void adb_wo_reset(struct adb_obj *o)
{
	uint32_t max = o->obj[ADBI_NUM_ENTRIES];
	memset(o->obj, 0, sizeof(adb_val_t[o->num]));
	o->obj[ADBI_NUM_ENTRIES] = max;
	o->num = 1;
}

void adb_wo_resetdb(struct adb_obj *o)
{
	adb_wo_reset(o);
	adb_reset(o->db);
}

static adb_val_t __adb_w_obj(struct adb_obj *o, uint32_t type)
{
	uint32_t n, max = o->obj[ADBI_NUM_ENTRIES];
	adb_val_t *obj = o->obj, val = ADB_NULL;

	if (o->schema && o->schema->pre_commit) o->schema->pre_commit(o);

	for (n = o->num; n > 1 && obj[n-1] == ADB_NULL; n--)
		;
	if (n > 1) {
		obj[ADBI_NUM_ENTRIES] = htole32(n);
		val = ADB_VAL(type, adb_w_data1(o->db, obj, sizeof(adb_val_t[n]), sizeof(adb_val_t)));
	}
	adb_wo_reset(o);
	o->obj[ADBI_NUM_ENTRIES] = max;
	return val;
}

adb_val_t adb_w_obj(struct adb_obj *o)
{
	return __adb_w_obj(o, ADB_TYPE_OBJECT);
}

adb_val_t adb_w_arr(struct adb_obj *o)
{
	return __adb_w_obj(o, ADB_TYPE_ARRAY);
}

adb_val_t adb_wo_fromstring(struct adb_obj *o, apk_blob_t val)
{
	adb_wo_reset(o);
	return o->schema->fromstring(o, val);
}

adb_val_t adb_wo_val(struct adb_obj *o, unsigned i, adb_val_t v)
{
	if (i >= o->obj[ADBI_NUM_ENTRIES]) return adb_w_error(o->db, E2BIG);
	if (ADB_IS_ERROR(v)) return adb_w_error(o->db, ADB_VAL_VALUE(v));
	if (v != ADB_NULL && i >= o->num) o->num = i + 1;
	return o->obj[i] = v;
}

adb_val_t adb_wo_val_fromstring(struct adb_obj *o, unsigned i, apk_blob_t val)
{
	if (i >= o->obj[ADBI_NUM_ENTRIES]) return adb_w_error(o->db, E2BIG);
	if (i >= o->num) o->num = i + 1;
	return o->obj[i] = adb_w_fromstring(o->db, o->schema->fields[i-1].kind, val);
}

adb_val_t adb_wo_int(struct adb_obj *o, unsigned i, uint32_t v)
{
	return adb_wo_val(o, i, adb_w_int(o->db, v));
}

adb_val_t adb_wo_blob(struct adb_obj *o, unsigned i, apk_blob_t b)
{
	assert(o->schema->kind == ADB_KIND_OBJECT);
	return adb_wo_val(o, i, adb_w_blob(o->db, b));
}

adb_val_t adb_wo_blob_raw(struct adb_obj *o, unsigned i, apk_blob_t b)
{
	assert(o->schema->kind == ADB_KIND_OBJECT);
	return adb_wo_val(o, i, adb_w_blob_raw(o->db, b));
}

adb_val_t adb_wo_obj(struct adb_obj *o, unsigned i, struct adb_obj *no)
{
	assert(o->schema->kind == ADB_KIND_OBJECT);
	assert(o->db == no->db);
	return adb_wo_val(o, i, adb_w_obj(no));
}

adb_val_t adb_wo_arr(struct adb_obj *o, unsigned i, struct adb_obj *no)
{
	assert(o->schema->kind == ADB_KIND_OBJECT || o->schema->kind == ADB_KIND_ARRAY);
	assert(o->db == no->db);
	return adb_wo_val(o, i, adb_w_arr(no));
}

adb_val_t adb_wa_append(struct adb_obj *o, adb_val_t v)
{
	assert(o->schema->kind == ADB_KIND_ARRAY);
	if (o->num >= o->obj[ADBI_NUM_ENTRIES]) return adb_w_error(o->db, E2BIG);
	if (ADB_IS_ERROR(v)) return adb_w_error(o->db, ADB_VAL_VALUE(v));
	if (v != ADB_VAL_NULL) o->obj[o->num++] = v;
	return v;
}

adb_val_t adb_wa_append_obj(struct adb_obj *o, struct adb_obj *no)
{
	assert(o->schema->kind == ADB_KIND_ARRAY);
	assert(o->db == no->db);
	return adb_wa_append(o, adb_w_obj(no));
}

adb_val_t adb_wa_append_fromstring(struct adb_obj *o, apk_blob_t b)
{
	assert(o->schema->kind == ADB_KIND_ARRAY);
	return adb_wa_append(o, adb_w_fromstring(o->db, o->schema->fields[0].kind, b));
}

void adb_wa_sort(struct adb_obj *arr)
{
	assert(arr->schema->kind == ADB_KIND_ARRAY);
	__db1 = __db2 = arr->db;
	switch (*arr->schema->fields[0].kind) {
	case ADB_KIND_OBJECT:
		__schema = container_of(arr->schema->fields[0].kind, struct adb_object_schema, kind);
		qsort(&arr->obj[ADBI_FIRST], adb_ra_num(arr), sizeof(arr->obj[0]), wacmp);
		break;
	case ADB_KIND_ADB:
		__schema = container_of(arr->schema->fields[0].kind, struct adb_adb_schema, kind)->schema;
		qsort(&arr->obj[ADBI_FIRST], adb_ra_num(arr), sizeof(arr->obj[0]), wadbcmp);
		break;
	default:
		assert(1);
	}
}

void adb_wa_sort_unique(struct adb_obj *arr)
{
	int i, j, num;

	adb_wa_sort(arr);
	num = adb_ra_num(arr);
	if (num >= 2) {
		for (i = 2, j = 2; i <= num; i++) {
			if (arr->obj[i] == arr->obj[i-1]) continue;
			arr->obj[j++] = arr->obj[i];
		}
		arr->num = j;
	}
}

/* Schema helpers */
int adb_s_field_by_name_blob(const struct adb_object_schema *schema, apk_blob_t blob)
{
	for (int i = 0; i < schema->num_fields-1 && schema->fields[i].name; i++)
		if (apk_blob_compare(APK_BLOB_STR(schema->fields[i].name), blob) == 0)
			return i + 1;
	return 0;
}

int adb_s_field_by_name(const struct adb_object_schema *schema, const char *name)
{
	for (int i = 0; i < schema->num_fields-1 && schema->fields[i].name; i++)
		if (strcmp(schema->fields[i].name, name) == 0)
			return i + 1;
	return 0;
}

/* Container creation */
int adb_c_header(struct apk_ostream *os, struct adb *db)
{
	struct adb_file_header hdr = {
		.magic = ADB_FORMAT_MAGIC,
		.schema = htole32(db->schema),
	};
	return apk_ostream_write(os, &hdr, sizeof hdr);
}

int adb_c_block(struct apk_ostream *os, uint32_t type, apk_blob_t val)
{
	struct adb_block blk = adb_block_init(type, val.len);
	size_t padding = adb_block_padding(&blk);
	int r;

	if (val.len & ~0x3fffffff) return -APKE_ADB_LIMIT;

	r = apk_ostream_write(os, &blk, sizeof blk);
	if (r < 0) return r;

	r = apk_ostream_write(os, val.ptr, val.len);
	if (r < 0) return r;

	if (padding) {
		r = apk_ostream_write(os, padding_zeroes, padding);
		if (r < 0) return r;
	}

	return 0;
}

int adb_c_block_data(struct apk_ostream *os, apk_blob_t hdr, uint32_t size, struct apk_istream *is)
{
	struct adb_block blk = adb_block_init(ADB_BLOCK_DATA, size + hdr.len);
	size_t padding = adb_block_padding(&blk);
	int r;

	if (IS_ERR(os)) return PTR_ERR(os);
	if (IS_ERR(is)) return apk_ostream_cancel(os, PTR_ERR(is));

	r = apk_ostream_write(os, &blk, sizeof blk);
	if (r < 0) return r;

	r = apk_ostream_write(os, hdr.ptr, hdr.len);
	if (r < 0) return r;

	r = apk_stream_copy(is, os, size, 0, 0, 0);
	if (r < 0) return r;

	if (padding) {
		r = apk_ostream_write(os, padding_zeroes, padding);
		if (r < 0) return r;
	}

	return apk_istream_close(is);
}

int adb_c_block_copy(struct apk_ostream *os, struct adb_block *b, struct apk_istream *is, struct adb_verify_ctx *vfy)
{
	size_t blk_sz = adb_block_length(b);
	size_t padding = adb_block_padding(b);
	int r;

	r = apk_ostream_write(os, b, sizeof *b);
	if (r < 0) return r;

	if (vfy) {
		struct apk_digest_ctx dctx;
		const uint8_t alg = APK_DIGEST_SHA512;

		apk_digest_ctx_init(&dctx, alg);
		r = apk_stream_copy(is, os, blk_sz, 0, 0, &dctx);
		apk_digest_ctx_final(&dctx, &vfy->sha512);
		vfy->calc |= (1 << alg);
		apk_digest_ctx_free(&dctx);
	} else {
		r = apk_stream_copy(is, os, blk_sz, 0, 0, 0);
	}
	if (r < 0) return r;
	r = 0;
	if (padding) {
		r = apk_ostream_write(os, padding_zeroes, padding);
		if (r < 0) return r;
	}
	return r;
}

int adb_c_adb(struct apk_ostream *os, struct adb *db, struct apk_trust *t)
{
	if (IS_ERR(os)) return PTR_ERR(os);
	if (!db->schema) return apk_ostream_cancel(os, -APKE_ADB_HEADER);

	adb_c_header(os, db);
	adb_c_block(os, ADB_BLOCK_ADB, db->adb);
	adb_trust_write_signatures(t, db, NULL, os);

	return apk_ostream_error(os);
}

int adb_c_create(struct apk_ostream *os, struct adb *db, struct apk_trust *t)
{
	adb_c_adb(os, db, t);
	return apk_ostream_close(os);
}

/* Signatures */
static int adb_digest_adb(struct adb_verify_ctx *vfy, unsigned int hash_alg, apk_blob_t data, apk_blob_t *pmd)
{
	struct apk_digest *d;
	int r;

	switch (hash_alg) {
	case APK_DIGEST_SHA512:
		d = &vfy->sha512;
		break;
	default:
		return -APKE_CRYPTO_NOT_SUPPORTED;
	}

	if (!(vfy->calc & (1 << hash_alg))) {
		if (APK_BLOB_IS_NULL(data)) return -APKE_ADB_BLOCK;
		r = apk_digest_calc(d, hash_alg, data.ptr, data.len);
		if (r != 0) return r;
		vfy->calc |= (1 << hash_alg);
	}

	*pmd = APK_DIGEST_BLOB(*d);
	return 0;
}

static int adb_digest_v0_signature(struct apk_digest_ctx *dctx, uint32_t schema, struct adb_sign_v0 *sig0, apk_blob_t md)
{
	int r;

	if ((r = apk_digest_ctx_update(dctx, &schema, sizeof schema)) != 0 ||
	    (r = apk_digest_ctx_update(dctx, sig0, sizeof *sig0)) != 0 ||
	    (r = apk_digest_ctx_update(dctx, md.ptr, md.len)) != 0)
		return r;
	return 0;
}

int adb_trust_write_signatures(struct apk_trust *trust, struct adb *db, struct adb_verify_ctx *vfy, struct apk_ostream *os)
{
	union {
		struct adb_sign_hdr hdr;
		struct adb_sign_v0 v0;
		unsigned char buf[ADB_MAX_SIGNATURE_LEN];
	} sig;
	struct apk_trust_key *tkey;
	apk_blob_t md;
	size_t siglen;
	int r;

	if (!vfy) {
		vfy = alloca(sizeof *vfy);
		memset(vfy, 0, sizeof *vfy);
	}

	r = adb_digest_adb(vfy, APK_DIGEST_SHA512, db->adb, &md);
	if (r) return r;

	list_for_each_entry(tkey, &trust->private_key_list, key_node) {
		sig.v0 = (struct adb_sign_v0) {
			.hdr.sign_ver = 0,
			.hdr.hash_alg = APK_DIGEST_SHA512,
		};
		memcpy(sig.v0.id, tkey->key.id, sizeof(sig.v0.id));

		siglen = sizeof sig.buf - sizeof sig.v0;

		if ((r = apk_sign_start(&trust->dctx, &tkey->key)) != 0 ||
		    (r = adb_digest_v0_signature(&trust->dctx, db->schema, &sig.v0, md)) != 0 ||
		    (r = apk_sign(&trust->dctx, sig.v0.sig, &siglen)) != 0)
			goto err;

		r = adb_c_block(os, ADB_BLOCK_SIG, APK_BLOB_PTR_LEN((char*) &sig, sizeof(sig.v0) + siglen));
		if (r < 0) goto err;
	}
	return 0;
err:
	apk_ostream_cancel(os, r);
	return r;
}

int adb_trust_verify_signature(struct apk_trust *trust, struct adb *db, struct adb_verify_ctx *vfy, apk_blob_t sigb)
{
	struct apk_trust_key *tkey;
	struct adb_sign_hdr *sig;
	struct adb_sign_v0 *sig0;
	apk_blob_t md;

	if (APK_BLOB_IS_NULL(db->adb)) return -APKE_ADB_BLOCK;
	if (sigb.len < sizeof(struct adb_sign_hdr)) return -APKE_ADB_SIGNATURE;

	sig  = (struct adb_sign_hdr *) sigb.ptr;
	sig0 = (struct adb_sign_v0 *) sigb.ptr;
	if (sig->sign_ver != 0) return -APKE_ADB_SIGNATURE;

	list_for_each_entry(tkey, &trust->trusted_key_list, key_node) {
		if (memcmp(sig0->id, tkey->key.id, sizeof sig0->id) != 0) continue;
		if (adb_digest_adb(vfy, sig->hash_alg, db->adb, &md) != 0) continue;

		if (apk_verify_start(&trust->dctx, &tkey->key) != 0 ||
		    adb_digest_v0_signature(&trust->dctx, db->schema, sig0, md) != 0 ||
		    apk_verify(&trust->dctx, sig0->sig, sigb.len - sizeof *sig0) != 0)
			continue;

		return 0;
	}

	return -APKE_SIGNATURE_UNTRUSTED;
}
