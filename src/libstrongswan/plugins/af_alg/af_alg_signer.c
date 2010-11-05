/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "af_alg_signer.h"

#include <unistd.h>
#include <errno.h>
#include <linux/socket.h>
#include <linux/if_alg.h>

#include <debug.h>

#ifndef AF_ALG
#define AF_ALG		38
#endif /* AF_ALG */

#ifndef SOL_ALG
#define SOL_ALG 279
#endif /* SOL_ALG */

typedef struct private_af_alg_signer_t private_af_alg_signer_t;

/**
 * Private data structure with signing context.
 */
struct private_af_alg_signer_t {

	/**
	 * Public interface of af_alg_signer_t.
	 */
	af_alg_signer_t public;

	/**
	 * Transform fd
	 */
	int tfm;

	/**
	 * Current operation fd, -1 if none
	 */
	int op;

	/**
	 * Size of the truncated signature
	 */
	size_t block_size;

	/**
	 * Default key size
	 */
	size_t key_size;
};

/**
 * Get the kernel algorithm string and block/key size for our identifier
 */
static size_t lookup_alg(integrity_algorithm_t algo, char *name,
						 size_t *key_size)
{
	static struct {
		integrity_algorithm_t id;
		char *name;
		size_t block_size;
		size_t key_size;
	} algs[] = {
		{AUTH_HMAC_MD5_96,			"hmac(md5)",		12,		16,	},
		{AUTH_HMAC_MD5_128,			"hmac(md5)",		16,		16,	},
		{AUTH_HMAC_SHA1_96,			"hmac(sha1)",		12,		20,	},
		{AUTH_HMAC_SHA1_128,		"hmac(sha1)",		16,		20,	},
		{AUTH_HMAC_SHA1_160,		"hmac(sha1)",		20,		20,	},
		{AUTH_HMAC_SHA2_256_96,		"hmac(sha256)",		12,		32,	},
		{AUTH_HMAC_SHA2_256_128,	"hmac(sha256)",		16,		32,	},
		{AUTH_HMAC_SHA2_256_256,	"hmac(sha384)",		32,		32,	},
		{AUTH_HMAC_SHA2_384_192,	"hmac(sha384)",		24,		48,	},
		{AUTH_HMAC_SHA2_384_384,	"hmac(sha384)",		48,		48,	},
		{AUTH_HMAC_SHA2_512_256,	"hmac(sha512)",		32,		64,	},
		{AUTH_AES_XCBC_96,			"xcbc(aes)",		12,		16,	},
		{AUTH_CAMELLIA_XCBC_96,		"xcbc(camellia)",	12,		16,	},
	};
	int i;

	for (i = 0; i < countof(algs); i++)
	{
		if (algs[i].id == algo)
		{
			strcpy(name, algs[i].name);
			*key_size = algs[i].key_size;
			return algs[i].block_size;
		}
	}
	return 0;
}

METHOD(signer_t, get_signature, void,
	private_af_alg_signer_t *this, chunk_t data, u_int8_t *buffer)
{
	ssize_t len;

	while (this->op == -1)
	{
		this->op = accept(this->tfm, NULL, 0);
		if (this->op == -1)
		{
			DBG1(DBG_LIB, "opening AF_ALG signer failed: %s", strerror(errno));
			sleep(1);
		}
	}
	do
	{
		len = send(this->op, data.ptr, data.len, buffer ? 0 : MSG_MORE);
		if (len == -1)
		{
			DBG1(DBG_LIB, "writing to AF_ALG signer failed: %s", strerror(errno));
			sleep(1);
		}
		else
		{
			data = chunk_skip(data, len);
		}
	}
	while (data.len);
	if (buffer)
	{
		while (read(this->op, buffer, this->block_size) != this->block_size)
		{
			DBG1(DBG_LIB, "reading AF_ALG signer failed: %s", strerror(errno));
			sleep(1);
		}
		close(this->op);
		this->op = -1;
	}
}

METHOD(signer_t, allocate_signature, void,
	private_af_alg_signer_t *this, chunk_t data, chunk_t *chunk)
{
	if (chunk)
	{
		*chunk = chunk_alloc(this->block_size);
		get_signature(this, data, chunk->ptr);
	}
	else
	{
		get_signature(this, data, NULL);
	}
}

METHOD(signer_t, verify_signature, bool,
	private_af_alg_signer_t *this, chunk_t data, chunk_t signature)
{
	char sig[this->block_size];

	if (signature.len != this->block_size)
	{
		return FALSE;
	}
	get_signature(this, data, sig);
	return memeq(signature.ptr, sig, signature.len);
}

METHOD(signer_t, get_key_size, size_t,
	private_af_alg_signer_t *this)
{
	return this->key_size;
}

METHOD(signer_t, get_block_size, size_t,
	private_af_alg_signer_t *this)
{
	return this->block_size;
}

METHOD(signer_t, set_key, void,
	private_af_alg_signer_t *this, chunk_t key)
{
	if (setsockopt(this->tfm, SOL_ALG, ALG_SET_KEY, key.ptr, key.len) == -1)
	{
		DBG1(DBG_LIB, "setting AF_ALG key failed: %s", strerror(errno));
	}
}

METHOD(signer_t, destroy, void,
	private_af_alg_signer_t *this)
{
	if (this->op != -1)
	{
		close(this->op);
	}
	close(this->tfm);
	free(this);
}

/*
 * Described in header
 */
af_alg_signer_t *af_alg_signer_create(integrity_algorithm_t algo)
{
	private_af_alg_signer_t *this;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};
	size_t block_size, key_size;

	block_size = lookup_alg(algo, sa.salg_name, &key_size);
	if (!block_size)
	{	/* not supported by kernel */
		return NULL;
	}

	INIT(this,
		.public = {
			.signer = {
				.get_signature = _get_signature,
				.allocate_signature = _allocate_signature,
				.verify_signature = _verify_signature,
				.get_key_size = _get_key_size,
				.get_block_size = _get_block_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.tfm = socket(AF_ALG, SOCK_SEQPACKET, 0),
		.op = -1,
		.block_size = block_size,
		.key_size = key_size,
	);

	if (this->tfm == -1)
	{
		DBG1(DBG_LIB, "opening AF_ALG socket failed: %s", strerror(errno));
		free(this);
		return NULL;
	}
	if (bind(this->tfm, (struct sockaddr*)&sa, sizeof(sa)) == -1)
	{
		DBG1(DBG_LIB, "binding AF_ALG socket for '%s' failed: %s",
			 sa.salg_name, strerror(errno));
		destroy(this);
		return NULL;
	}
	return &this->public;
}
