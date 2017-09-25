/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BR_BEARSSL_AEAD_H__
#define BR_BEARSSL_AEAD_H__

#include <stddef.h>
#include <stdint.h>

#include "bearssl_block.h"
#include "bearssl_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \file bearssl_aead.h
 *
 * # Authenticated Encryption with Additional Data
 *
 * This file documents the API for AEAD encryption.
 *
 *
 * ## Procedural API
 *
 * An AEAD algorithm processes messages and provides confidentiality
 * (encryption) and checked integrity (MAC). It uses the following
 * parameters:
 *
 *   - A symmetric key. Exact size depends on the AEAD algorithm.
 *
 *   - A nonce (IV). Size depends on the AEAD algorithm; for most
 *     algorithms, it is crucial for security that any given nonce
 *     value is never used twice for the same key and distinct
 *     messages.
 *
 *   - Data to encrypt and protect.
 *
 *   - Additional authenticated data, which is covered by the MAC but
 *     otherwise left untouched (i.e. not encrypted).
 *
 * The AEAD algorithm encrypts the data, and produces an authentication
 * tag. It is assumed that the encrypted data, the tag, the additional
 * authenticated data and the nonce are sent to the receiver; the
 * additional data and the nonce may be implicit (e.g. using elements of
 * the underlying transport protocol, such as record sequence numbers).
 * The receiver will recompute the tag value and compare it with the one
 * received; if they match, then the data is correct, and can be
 * decrypted and used; otherwise, at least one of the elements was
 * altered in transit, normally leading to wholesale rejection of the
 * complete message.
 *
 * For each AEAD algorithm, identified by a symbolic name (hereafter
 * denoted as "`xxx`"), the following functions are defined:
 *
 *   - `br_xxx_init()`
 *
 *     Initialise the AEAD algorithm, on a provided context structure.
 *     Exact parameters depend on the algorithm, and may include
 *     pointers to extra implementations and context structures. The
 *     secret key is provided at this point, either directly or
 *     indirectly.
 *
 *   - `br_xxx_reset()`
 *
 *     Start a new AEAD computation. The nonce value is provided as
 *     parameter to this function.
 *
 *   - `br_xxx_aad_inject()`
 *
 *     Inject some additional authenticated data. Additional data may
 *     be provided in several chunks of arbitrary length.
 *
 *   - `br_xxx_flip()`
 *
 *     This function MUST be called after injecting all additional
 *     authenticated data, and before beginning to encrypt the plaintext
 *     (or decrypt the ciphertext).
 *
 *   - `br_xxx_run()`
 *
 *     Process some plaintext (to encrypt) or ciphertext (to decrypt).
 *     Encryption/decryption is done in place. Data may be provided in
 *     several chunks of arbitrary length.
 *
 *   - `br_xxx_get_tag()`
 *
 *     Compute the authentication tag. All message data (encrypted or
 *     decrypted) must have been injected at that point. Also, this
 *     call may modify internal context elements, so it may be called
 *     only once for a given AEAD computation.
 *
 *   - `br_xxx_check_tag()`
 *
 *     An alternative to `br_xxx_get_tag()`, meant to be used by the
 *     receiver: the authentication tag is internally recomputed, and
 *     compared with the one provided as parameter.
 *
 * This API makes the following assumptions on the AEAD algorithm:
 *
 *   - Encryption does not expand the size of the ciphertext; there is
 *     no padding. This is true of most modern AEAD modes such as GCM.
 *
 *   - The additional authenticated data must be processed first,
 *     before the encrypted/decrypted data.
 *
 *   - Nonce, plaintext and additional authenticated data all consist
 *     in an integral number of bytes. There is no provision to use
 *     elements whose lengh in bits is not a multiple of 8.
 *
 * Each AEAD algorithm has its own requirements and limits on the sizes
 * of additional data and plaintext. This API does not provide any
 * way to report invalid usage; it is up to the caller to ensure that
 * the provided key, nonce, and data elements all fit the algorithm's
 * requirements.
 *
 *
 * ## Object-Oriented API
 *
 * Each context structure begins with a field (called `vtable`) that
 * points to an instance of a structure that references the relevant
 * functions through pointers. Each such structure contains the
 * following:
 *
 *   - `reset`
 *
 *     Pointer to the reset function, that allows starting a new
 *     computation.
 *
 *   - `aad_inject`
 *
 *     Pointer to the additional authenticated data injection function.
 *
 *   - `flip`
 *
 *     Pointer to the function that transitions from additional data
 *     to main message data processing.
 *
 *   - `get_tag`
 *
 *     Pointer to the function that computes and returns the tag.
 *
 *   - `check_tag`
 *
 *     Pointer to the function that computes and verifies the tag against
 *     a received value.
 *
 * Note that there is no OOP method for context initialisation: the
 * various AEAD algorithms have different requirements that would not
 * map well to a single initialisation API.
 */

/**
 * \brief Class type of an AEAD algorithm.
 */
typedef struct br_aead_class_ br_aead_class;
struct br_aead_class_ {

	/**
	 * \brief Size (in bytes) of authentication tags created by
	 * this AEAD algorithm.
	 */
	size_t tag_size;

	/**
	 * \brief Reset an AEAD context.
	 *
	 * This function resets an already initialised AEAD context for
	 * a new computation run. Implementations and keys are
	 * conserved. This function can be called at any time; it
	 * cancels any ongoing AEAD computation that uses the provided
	 * context structure.

	 * The provided IV is a _nonce_. Each AEAD algorithm has its
	 * own requirements on IV size and contents; for most of them,
	 * it is crucial to security that each nonce value is used
	 * only once for a given secret key.
	 *
	 * \param cc    AEAD context structure.
	 * \param iv    AEAD nonce to use.
	 * \param len   AEAD nonce length (in bytes).
	 */
	void (*reset)(const br_aead_class **cc, const void *iv, size_t len);

	/**
	 * \brief Inject additional authenticated data.
	 *
	 * The provided data is injected into a running AEAD
	 * computation. Additional data must be injected _before_ the
	 * call to `flip()`. Additional data can be injected in several
	 * chunks of arbitrary length.
	 *
	 * \param cc     AEAD context structure.
	 * \param data   pointer to additional authenticated data.
	 * \param len    length of additiona authenticated data (in bytes).
	 */
	void (*aad_inject)(const br_aead_class **cc,
		const void *data, size_t len);

	/**
	 * \brief Finish injection of additional authenticated data.
	 *
	 * This function MUST be called before beginning the actual
	 * encryption or decryption (with `run()`), even if no
	 * additional authenticated data was injected. No additional
	 * authenticated data may be injected after this function call.
	 *
	 * \param cc   AEAD context structure.
	 */
	void (*flip)(const br_aead_class **cc);

	/**
	 * \brief Encrypt or decrypt some data.
	 *
	 * Data encryption or decryption can be done after `flip()` has
	 * been called on the context. If `encrypt` is non-zero, then
	 * the provided data shall be plaintext, and it is encrypted in
	 * place. Otherwise, the data shall be ciphertext, and it is
	 * decrypted in place.
	 *
	 * Data may be provided in several chunks of arbitrary length.
	 *
	 * \param cc        AEAD context structure.
	 * \param encrypt   non-zero for encryption, zero for decryption.
	 * \param data      data to encrypt or decrypt.
	 * \param len       data length (in bytes).
	 */
	void (*run)(const br_aead_class **cc, int encrypt,
		void *data, size_t len);

	/**
	 * \brief Compute authentication tag.
	 *
	 * Compute the AEAD authentication tag. The tag length depends
	 * on the AEAD algorithm; it is written in the provided `tag`
	 * buffer. This call terminates the AEAD run: no data may be
	 * processed with that AEAD context afterwards, until `reset()`
	 * is called to initiate a new AEAD run.
	 *
	 * The tag value must normally be sent along with the encrypted
	 * data. When decrypting, the tag value must be recomputed and
	 * compared with the received tag: if the two tag values differ,
	 * then either the tag or the encrypted data was altered in
	 * transit. As an alternative to this function, the
	 * `check_tag()` function may be used to compute and check the
	 * tag value.
	 *
	 * \param cc    AEAD context structure.
	 * \param tag   destination buffer for the tag.
	 */
	void (*get_tag)(const br_aead_class **cc, void *tag);

	/**
	 * \brief Compute and check authentication tag.
	 *
	 * This function is an alternative to `get_tag()`, and is
	 * normally used on the receiving end (i.e. when decrypting
	 * messages). The tag value is recomputed and compared with the
	 * provided tag value. If they match, 1 is returned; on
	 * mismatch, 0 is returned. A returned value of 0 means that the
	 * data or the tag was altered in transit, normally leading to
	 * wholesale rejection of the complete message.
	 *
	 * \param cc    AEAD context structure.
	 * \param tag   tag value to compare with (16 bytes).
	 * \return  1 on success (exact match of tag value), 0 otherwise.
	 */
	uint32_t (*check_tag)(const br_aead_class **cc, const void *tag);
};

/**
 * \brief Context structure for GCM.
 *
 * GCM is an AEAD mode that combines a block cipher in CTR mode with a
 * MAC based on GHASH, to provide authenticated encryption:
 *
 *   - Any block cipher with 16-byte blocks can be used with GCM.
 *
 *   - The nonce can have any length, from 0 up to 2^64-1 bits; however,
 *     96-bit nonces (12 bytes) are recommended (nonces with a length
 *     distinct from 12 bytes are internally hashed, which risks reusing
 *     nonce value with a small but not always negligible probability).
 *
 *   - Additional authenticated data may have length up to 2^64-1 bits.
 *
 *   - Message length may range up to 2^39-256 bits at most.
 *
 *   - The authentication tag has length 16 bytes.
 *
 * The GCM initialisation function receives as parameter an
 * _initialised_ block cipher implementation context, with the secret
 * key already set. A pointer to that context will be kept within the
 * GCM context structure. It is up to the caller to allocate and
 * initialise that block cipher context.
 */
typedef struct {
	/** \brief Pointer to vtable for this context. */
	const br_aead_class *vtable;

#ifndef BR_DOXYGEN_IGNORE
	const br_block_ctr_class **bctx;
	br_ghash gh;
	unsigned char h[16];
	unsigned char j0_1[12];
	unsigned char buf[16];
	unsigned char y[16];
	uint32_t j0_2, jc;
	uint64_t count_aad, count_ctr;
#endif
} br_gcm_context;

/**
 * \brief Initialize a GCM context.
 *
 * A block cipher implementation, with its initialised context structure,
 * is provided. The block cipher MUST use 16-byte blocks in CTR mode,
 * and its secret key MUST have been already set in the provided context.
 * A GHASH implementation must also be provided. The parameters are linked
 * in the GCM context.
 *
 * After this function has been called, the `br_gcm_reset()` function must
 * be called, to provide the IV for GCM computation.
 *
 * \param ctx    GCM context structure.
 * \param bctx   block cipher context (already initialised with secret key).
 * \param gh     GHASH implementation.
 */
void br_gcm_init(br_gcm_context *ctx,
	const br_block_ctr_class **bctx, br_ghash gh);

/**
 * \brief Reset a GCM context.
 *
 * This function resets an already initialised GCM context for a new
 * computation run. Implementations and keys are conserved. This function
 * can be called at any time; it cancels any ongoing GCM computation that
 * uses the provided context structure.
 *
 * The provided IV is a _nonce_. It is critical to GCM security that IV
 * values are not repeated for the same encryption key. IV can have
 * arbitrary length (up to 2^64-1 bits), but the "normal" length is
 * 96 bits (12 bytes).
 *
 * \param ctx   GCM context structure.
 * \param iv    GCM nonce to use.
 * \param len   GCM nonce length (in bytes).
 */
void br_gcm_reset(br_gcm_context *ctx, const void *iv, size_t len);

/**
 * \brief Inject additional authenticated data into GCM.
 *
 * The provided data is injected into a running GCM computation. Additional
 * data must be injected _before_ the call to `br_gcm_flip()`.
 * Additional data can be injected in several chunks of arbitrary length;
 * the maximum total size of additional authenticated data is 2^64-1
 * bits.
 *
 * \param ctx    GCM context structure.
 * \param data   pointer to additional authenticated data.
 * \param len    length of additiona authenticated data (in bytes).
 */
void br_gcm_aad_inject(br_gcm_context *ctx, const void *data, size_t len);

/**
 * \brief Finish injection of additional authenticated data into GCM.
 *
 * This function MUST be called before beginning the actual encryption
 * or decryption (with `br_gcm_run()`), even if no additional authenticated
 * data was injected. No additional authenticated data may be injected
 * after this function call.
 *
 * \param ctx   GCM context structure.
 */
void br_gcm_flip(br_gcm_context *ctx);

/**
 * \brief Encrypt or decrypt some data with GCM.
 *
 * Data encryption or decryption can be done after `br_gcm_flip()`
 * has been called on the context. If `encrypt` is non-zero, then the
 * provided data shall be plaintext, and it is encrypted in place.
 * Otherwise, the data shall be ciphertext, and it is decrypted in place.
 *
 * Data may be provided in several chunks of arbitrary length. The maximum
 * total length for data is 2^39-256 bits, i.e. about 65 gigabytes.
 *
 * \param ctx       GCM context structure.
 * \param encrypt   non-zero for encryption, zero for decryption.
 * \param data      data to encrypt or decrypt.
 * \param len       data length (in bytes).
 */
void br_gcm_run(br_gcm_context *ctx, int encrypt, void *data, size_t len);

/**
 * \brief Compute GCM authentication tag.
 *
 * Compute the GCM authentication tag. The tag is a 16-byte value which
 * is written in the provided `tag` buffer. This call terminates the
 * GCM run: no data may be processed with that GCM context afterwards,
 * until `br_gcm_reset()` is called to initiate a new GCM run.
 *
 * The tag value must normally be sent along with the encrypted data.
 * When decrypting, the tag value must be recomputed and compared with
 * the received tag: if the two tag values differ, then either the tag
 * or the encrypted data was altered in transit. As an alternative to
 * this function, the `br_gcm_check_tag()` function can be used to
 * compute and check the tag value.
 *
 * \param ctx   GCM context structure.
 * \param tag   destination buffer for the tag (16 bytes).
 */
void br_gcm_get_tag(br_gcm_context *ctx, void *tag);

/**
 * \brief Compute and check GCM authentication tag.
 *
 * This function is an alternative to `br_gcm_get_tag()`, normally used
 * on the receiving end (i.e. when decrypting value). The tag value is
 * recomputed and compared with the provided tag value. If they match, 1
 * is returned; on mismatch, 0 is returned. A returned value of 0 means
 * that the data or the tag was altered in transit, normally leading to
 * wholesale rejection of the complete message.
 *
 * \param ctx   GCM context structure.
 * \param tag   tag value to compare with (16 bytes).
 * \return  1 on success (exact match of tag value), 0 otherwise.
 */
uint32_t br_gcm_check_tag(br_gcm_context *ctx, const void *tag);

/**
 * \brief Class instance for GCM.
 */
extern const br_aead_class br_gcm_vtable;

#ifdef __cplusplus
}
#endif

#endif
