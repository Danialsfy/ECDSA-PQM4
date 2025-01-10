#ifndef P256_UTIL_H
#define P256_UTIL_H

#include <stdint.h>
#include <stdbool.h>

// Struct for signing precomputation
struct SignPrecomp {
    uint32_t k_inv[8]; // Multiplicative inverse of k
    uint32_t r[8];     // Component of signature
};

// Function declarations for modular arithmetic
bool P256_check_range_n(const uint32_t n[8]); // Validate range of scalar
bool P256_check_range_p(const uint32_t p[8]); // Validate range of curve point
void P256_reduce_mod_n_32bytes(uint32_t out[8], const uint32_t in[8]); // Reduce scalar modulo n
void P256_mul_mod_n(uint32_t u1[8], const uint32_t z[8], const uint32_t w[8]); // Multiplication mod n
void P256_add_mod_n(uint32_t u2[8], const uint32_t r[8], const uint32_t w[8]); // Addition mod n
void P256_from_montgomery(uint32_t out[8], const uint32_t in[8]); // Convert from Montgomery form
void P256_to_montgomery(uint32_t out[8], const uint32_t in[8]);   // Convert to Montgomery form

// Function declarations for elliptic curve operations
bool P256_point_is_on_curve(const uint32_t x[8], const uint32_t y[8]); // Validate if a point is on the curve
bool p256_keygen(uint32_t public_key_x[8], uint32_t public_key_y[8], const uint32_t private_key[8]); // Generate key pair
// void scalarmult_fixed_base(uint32_t out_x[8], uint32_t out_y[8], const uint32_t scalar[8]); // Scalar multiplication with base point
bool p256_verify(const uint32_t public_key_x[8], const uint32_t public_key_y[8], const uint8_t* hash, uint32_t hashlen_in_bytes, const uint32_t r[8], const uint32_t s[8]); // Verify ECDSA signature

// Function declarations for ECDSA signing
bool p256_sign_step1(struct SignPrecomp *result, const uint32_t k[8]); // Precompute values for signing
bool p256_sign_step2(uint32_t r[8], uint32_t s[8], const uint8_t *hash, uint32_t hash_len, const uint32_t private_key[8], struct SignPrecomp *sign_precomp); // Generate r, s

// Hashing utility (to be replaced with appropriate implementation)
void sha256(uint8_t *out, const uint8_t *in, size_t inlen); // Hash function placeholder

// Endianness conversion
void p256_convert_endianness(void *output, const void *input, size_t byte_len); // Convert between big-endian and little-endian as needed

#endif // P256_UTIL_H
