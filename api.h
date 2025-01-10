#ifndef API_H
#define API_H

#include <stdint.h>
#include <stddef.h>

// Sizes defined as per PQM4 requirements
#define CRYPTO_SECRETKEYBYTES 32 // 256-bit private key
#define CRYPTO_PUBLICKEYBYTES 64 // 256-bit x and y coordinates of public key
#define CRYPTO_BYTES 64          // 64 bytes for (r, s) signature

// API functions
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign(unsigned char *sm, size_t *smlen, const unsigned char *msg, size_t len, const unsigned char *sk);
int crypto_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk);

#endif // P256_ECDSA_PQM4_H