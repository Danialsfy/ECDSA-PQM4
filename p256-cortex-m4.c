#include "api.h"
#include "p256-cortex-m4-config.h"
#include "p256_util.h"
#include <string.h>
#include <randombytes.h>
#include <stdint.h>
#include <sha2.h>


// Helper macros for random number generation
extern int randombytes(unsigned char *buf, size_t len);

// Generate key pair
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    uint32_t private_key[8], public_key_x[8], public_key_y[8];

    // Generate a random 256-bit private key
    randombytes((unsigned char *)private_key, CRYPTO_SECRETKEYBYTES);
    P256_reduce_mod_n_32bytes(private_key, private_key); // Ensure it's in range

    // Generate public key
    if (!p256_keygen(public_key_x, public_key_y, private_key)) {
        return -1; // Error during key generation
    }

    // Store public key
    p256_convert_endianness(pk, public_key_x, 32);
    p256_convert_endianness(pk + 32, public_key_y, 32);

    // Store private key
    memcpy(sk, private_key, CRYPTO_SECRETKEYBYTES);
    return 0;
}

// Sign a message
int crypto_sign(unsigned char *sm, size_t *smlen, const unsigned char *msg, size_t len, const unsigned char *sk) {
    uint32_t private_key[8], k[8], r[8], s[8];
    uint8_t hash[32]; // Message digest
    struct SignPrecomp precomp;

    // Convert private key to internal format
    memcpy(private_key, sk, CRYPTO_SECRETKEYBYTES);

    // Compute the SHA-256 hash of the message
    sha256(hash, msg, len);

    // Generate a random ephemeral key k
    randombytes((unsigned char *)k, CRYPTO_SECRETKEYBYTES);
    P256_reduce_mod_n_32bytes(k, k);

    // Step 1 and Step 2 of the signing process
    if (!p256_sign_step1(&precomp, k) || !p256_sign_step2(r, s, hash, sizeof(hash), private_key, &precomp)) {
        return -1; // Error during signing
    }

    // Serialize the signature
    p256_convert_endianness(sm, r, 32);
    p256_convert_endianness(sm + 32, s, 32);

    // Append the original message to the signature
    memcpy(sm + CRYPTO_BYTES, msg, len);

    // Set the total signature length
    *smlen = CRYPTO_BYTES + len;
    return 0;
}

// Verify a signature
int crypto_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk) {
    uint32_t public_key_x[8], public_key_y[8], r[8], s[8];
    uint8_t hash[32];

    if (smlen < CRYPTO_BYTES) {
        return -1; // Invalid signature length
    }

    // Deserialize the public key
    p256_convert_endianness((uint8_t *)public_key_x, (const uint32_t *)pk, 32);
    p256_convert_endianness((uint8_t *)public_key_y, (const uint32_t *)(pk + 32), 32);

    // Deserialize the signature
    p256_convert_endianness((uint8_t *)r, (const uint32_t *)sm, 32);
    p256_convert_endianness((uint8_t *)s, (const uint32_t *)(sm + 32), 32);

    // Recover the original message
    *mlen = smlen - CRYPTO_BYTES;
    memcpy(m, sm + CRYPTO_BYTES, *mlen);

    // Compute the SHA-256 hash of the message
    sha256(hash, m, *mlen);

    // Verify the signature (r, s)
    if (!p256_verify(public_key_x, public_key_y, hash, sizeof(hash), r, s)) {
        return -1; // Signature verification failed
    }

    return 0;
}
