#include "ripemd160_avx2.h"
#include <immintrin.h>
#include <cstring>
#include <cstdint>

namespace ripemd160avx2 {

#ifdef WIN64
static const __declspec(align(32)) uint32_t _init[] = {
#else
static const uint32_t _init[] __attribute__((aligned(32))) = {
#endif
    // 8 copies of A
    0x67452301ul, 0x67452301ul, 0x67452301ul, 0x67452301ul,
    0x67452301ul, 0x67452301ul, 0x67452301ul, 0x67452301ul,

    // 8 copies of B
    0xEFCDAB89ul, 0xEFCDAB89ul, 0xEFCDAB89ul, 0xEFCDAB89ul,
    0xEFCDAB89ul, 0xEFCDAB89ul, 0xEFCDAB89ul, 0xEFCDAB89ul,

    // 8 copies of C
    0x98BADCFEul, 0x98BADCFEul, 0x98BADCFEul, 0x98BADCFEul,
    0x98BADCFEul, 0x98BADCFEul, 0x98BADCFEul, 0x98BADCFEul,

    // 8 copies of D
    0x10325476ul, 0x10325476ul, 0x10325476ul, 0x10325476ul,
    0x10325476ul, 0x10325476ul, 0x10325476ul, 0x10325476ul,

    // 8 copies of E
    0xC3D2E1F0ul, 0xC3D2E1F0ul, 0xC3D2E1F0ul, 0xC3D2E1F0ul,
    0xC3D2E1F0ul, 0xC3D2E1F0ul, 0xC3D2E1F0ul, 0xC3D2E1F0ul
};

// AVX2 operations
#define _mm256_not_si256(x) _mm256_xor_si256((x), _mm256_set1_epi32(-1))
#define ROL(x, n) _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n))

// RIPEMD-160 functions
#define f1(x, y, z) _mm256_xor_si256(x, _mm256_xor_si256(y, z))
#define f2(x, y, z) _mm256_or_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z))
#define f3(x, y, z) _mm256_xor_si256(_mm256_or_si256(x, _mm256_not_si256(y)), z)
#define f4(x, y, z) _mm256_or_si256(_mm256_and_si256(x, z), _mm256_andnot_si256(z, y))
#define f5(x, y, z) _mm256_xor_si256(x, _mm256_or_si256(y, _mm256_not_si256(z)))

// Adding helpers
#define add3(x0, x1, x2) _mm256_add_epi32(_mm256_add_epi32(x0, x1), x2)
#define add4(x0, x1, x2, x3) _mm256_add_epi32(_mm256_add_epi32(x0, x1), _mm256_add_epi32(x2, x3))

// Round function
#define Round(a, b, c, d, e, f, x, k, r)   \
    u = add4(a, f, x, _mm256_set1_epi32(k)); \
    a = _mm256_add_epi32(ROL(u, r), e);     \
    c = ROL(c, 10);

// Macroses for each round
#define R11(a, b, c, d, e, x, r) Round(a, b, c, d, e, f1(b, c, d), x, 0, r)
#define R21(a, b, c, d, e, x, r) Round(a, b, c, d, e, f2(b, c, d), x, 0x5A827999ul, r)
#define R31(a, b, c, d, e, x, r) Round(a, b, c, d, e, f3(b, c, d), x, 0x6ED9EBA1ul, r)
#define R41(a, b, c, d, e, x, r) Round(a, b, c, d, e, f4(b, c, d), x, 0x8F1BBCDCul, r)
#define R51(a, b, c, d, e, x, r) Round(a, b, c, d, e, f5(b, c, d), x, 0xA953FD4Eul, r)
#define R12(a, b, c, d, e, x, r) Round(a, b, c, d, e, f5(b, c, d), x, 0x50A28BE6ul, r)
#define R22(a, b, c, d, e, x, r) Round(a, b, c, d, e, f4(b, c, d), x, 0x5C4DD124ul, r)
#define R32(a, b, c, d, e, x, r) Round(a, b, c, d, e, f3(b, c, d), x, 0x6D703EF3ul, r)
#define R42(a, b, c, d, e, x, r) Round(a, b, c, d, e, f2(b, c, d), x, 0x7A6D76E9ul, r)
#define R52(a, b, c, d, e, x, r) Round(a, b, c, d, e, f1(b, c, d), x, 0, r)

// Macros to load words from the message blocks
#define LOADW(i) _mm256_set_epi32(*((uint32_t *)blk[0] + i), *((uint32_t *)blk[1] + i), \
                                  *((uint32_t *)blk[2] + i), *((uint32_t *)blk[3] + i), \
                                  *((uint32_t *)blk[4] + i), *((uint32_t *)blk[5] + i), \
                                  *((uint32_t *)blk[6] + i), *((uint32_t *)blk[7] + i))

// Initialize state 
void Initialize(__m256i *s) {
    memcpy(s, _init, sizeof(_init));
}

// Transform function processes one block for each message
void Transform(__m256i *s, uint8_t *blk[8]) {
    // Load state variables
    __m256i a1 = _mm256_load_si256(s + 0);
    __m256i b1 = _mm256_load_si256(s + 1);
    __m256i c1 = _mm256_load_si256(s + 2);
    __m256i d1 = _mm256_load_si256(s + 3);
    __m256i e1 = _mm256_load_si256(s + 4);

    // Initialize second set of variables
    __m256i a2 = a1;
    __m256i b2 = b1;
    __m256i c2 = c1;
    __m256i d2 = d1;
    __m256i e2 = e1;

    __m256i u;
    __m256i w[16];

    for (int i = 0; i < 16; ++i) {
        w[i] = LOADW(i);
    }

    // Main rounds 0-15 of Riepmd160
    R11(a1, b1, c1, d1, e1, w[0], 11);
    R12(a2, b2, c2, d2, e2, w[5], 8);
    R11(e1, a1, b1, c1, d1, w[1], 14);
    R12(e2, a2, b2, c2, d2, w[14], 9);
    R11(d1, e1, a1, b1, c1, w[2], 15);
    R12(d2, e2, a2, b2, c2, w[7], 9);
    R11(c1, d1, e1, a1, b1, w[3], 12);
    R12(c2, d2, e2, a2, b2, w[0], 11);
    R11(b1, c1, d1, e1, a1, w[4], 5);
    R12(b2, c2, d2, e2, a2, w[9], 13);
    R11(a1, b1, c1, d1, e1, w[5], 8);
    R12(a2, b2, c2, d2, e2, w[2], 15);
    R11(e1, a1, b1, c1, d1, w[6], 7);
    R12(e2, a2, b2, c2, d2, w[11], 15);
    R11(d1, e1, a1, b1, c1, w[7], 9);
    R12(d2, e2, a2, b2, c2, w[4], 5);
    R11(c1, d1, e1, a1, b1, w[8], 11);
    R12(c2, d2, e2, a2, b2, w[13], 7);
    R11(b1, c1, d1, e1, a1, w[9], 13);
    R12(b2, c2, d2, e2, a2, w[6], 7);
    R11(a1, b1, c1, d1, e1, w[10], 14);
    R12(a2, b2, c2, d2, e2, w[15], 8);
    R11(e1, a1, b1, c1, d1, w[11], 15);
    R12(e2, a2, b2, c2, d2, w[8], 11);
    R11(d1, e1, a1, b1, c1, w[12], 6);
    R12(d2, e2, a2, b2, c2, w[1], 14);
    R11(c1, d1, e1, a1, b1, w[13], 7);
    R12(c2, d2, e2, a2, b2, w[10], 14);
    R11(b1, c1, d1, e1, a1, w[14], 9);
    R12(b2, c2, d2, e2, a2, w[3], 12);
    R11(a1, b1, c1, d1, e1, w[15], 8);
    R12(a2, b2, c2, d2, e2, w[12], 6);

    R21(e1, a1, b1, c1, d1, w[7], 7);
    R22(e2, a2, b2, c2, d2, w[6], 9);
    R21(d1, e1, a1, b1, c1, w[4], 6);
    R22(d2, e2, a2, b2, c2, w[11], 13);
    R21(c1, d1, e1, a1, b1, w[13], 8);
    R22(c2, d2, e2, a2, b2, w[3], 15);
    R21(b1, c1, d1, e1, a1, w[1], 13);
    R22(b2, c2, d2, e2, a2, w[7], 7);
    R21(a1, b1, c1, d1, e1, w[10], 11);
    R22(a2, b2, c2, d2, e2, w[0], 12);
    R21(e1, a1, b1, c1, d1, w[6], 9);
    R22(e2, a2, b2, c2, d2, w[13], 8);
    R21(d1, e1, a1, b1, c1, w[15], 7);
    R22(d2, e2, a2, b2, c2, w[5], 9);
    R21(c1, d1, e1, a1, b1, w[3], 15);
    R22(c2, d2, e2, a2, b2, w[10], 11);
    R21(b1, c1, d1, e1, a1, w[12], 7);
    R22(b2, c2, d2, e2, a2, w[14], 7);
    R21(a1, b1, c1, d1, e1, w[0], 12);
    R22(a2, b2, c2, d2, e2, w[15], 7);
    R21(e1, a1, b1, c1, d1, w[9], 15);
    R22(e2, a2, b2, c2, d2, w[8], 12);
    R21(d1, e1, a1, b1, c1, w[5], 9);
    R22(d2, e2, a2, b2, c2, w[12], 7);
    R21(c1, d1, e1, a1, b1, w[2], 11);
    R22(c2, d2, e2, a2, b2, w[4], 6);
    R21(b1, c1, d1, e1, a1, w[14], 7);
    R22(b2, c2, d2, e2, a2, w[9], 15);
    R21(a1, b1, c1, d1, e1, w[11], 13);
    R22(a2, b2, c2, d2, e2, w[1], 13);
    R21(e1, a1, b1, c1, d1, w[8], 12);
    R22(e2, a2, b2, c2, d2, w[2], 11);

    R31(d1, e1, a1, b1, c1, w[3], 11);
    R32(d2, e2, a2, b2, c2, w[15], 9);
    R31(c1, d1, e1, a1, b1, w[10], 13);
    R32(c2, d2, e2, a2, b2, w[5], 7);
    R31(b1, c1, d1, e1, a1, w[14], 6);
    R32(b2, c2, d2, e2, a2, w[1], 15);
    R31(a1, b1, c1, d1, e1, w[4], 7);
    R32(a2, b2, c2, d2, e2, w[3], 11);
    R31(e1, a1, b1, c1, d1, w[9], 14);
    R32(e2, a2, b2, c2, d2, w[7], 8);
    R31(d1, e1, a1, b1, c1, w[15], 9);
    R32(d2, e2, a2, b2, c2, w[14], 6);
    R31(c1, d1, e1, a1, b1, w[8], 13);
    R32(c2, d2, e2, a2, b2, w[6], 6);
    R31(b1, c1, d1, e1, a1, w[1], 15);
    R32(b2, c2, d2, e2, a2, w[9], 14);
    R31(a1, b1, c1, d1, e1, w[2], 14);
    R32(a2, b2, c2, d2, e2, w[11], 12);
    R31(e1, a1, b1, c1, d1, w[7], 8);
    R32(e2, a2, b2, c2, d2, w[8], 13);
    R31(d1, e1, a1, b1, c1, w[0], 13);
    R32(d2, e2, a2, b2, c2, w[12], 5);
    R31(c1, d1, e1, a1, b1, w[6], 6);
    R32(c2, d2, e2, a2, b2, w[2], 14);
    R31(b1, c1, d1, e1, a1, w[13], 5);
    R32(b2, c2, d2, e2, a2, w[10], 13);
    R31(a1, b1, c1, d1, e1, w[11], 12);
    R32(a2, b2, c2, d2, e2, w[0], 13);
    R31(e1, a1, b1, c1, d1, w[5], 7);
    R32(e2, a2, b2, c2, d2, w[4], 7);
    R31(d1, e1, a1, b1, c1, w[12], 5);
    R32(d2, e2, a2, b2, c2, w[13], 5);

    R41(c1, d1, e1, a1, b1, w[1], 11);
    R42(c2, d2, e2, a2, b2, w[8], 15);
    R41(b1, c1, d1, e1, a1, w[9], 12);
    R42(b2, c2, d2, e2, a2, w[6], 5);
    R41(a1, b1, c1, d1, e1, w[11], 14);
    R42(a2, b2, c2, d2, e2, w[4], 8);
    R41(e1, a1, b1, c1, d1, w[10], 15);
    R42(e2, a2, b2, c2, d2, w[1], 11);
    R41(d1, e1, a1, b1, c1, w[0], 14);
    R42(d2, e2, a2, b2, c2, w[3], 14);
    R41(c1, d1, e1, a1, b1, w[8], 15);
    R42(c2, d2, e2, a2, b2, w[11], 14);
    R41(b1, c1, d1, e1, a1, w[12], 9);
    R42(b2, c2, d2, e2, a2, w[15], 6);
    R41(a1, b1, c1, d1, e1, w[4], 8);
    R42(a2, b2, c2, d2, e2, w[0], 14);
    R41(e1, a1, b1, c1, d1, w[13], 9);
    R42(e2, a2, b2, c2, d2, w[5], 6);
    R41(d1, e1, a1, b1, c1, w[3], 14);
    R42(d2, e2, a2, b2, c2, w[12], 9);
    R41(c1, d1, e1, a1, b1, w[7], 5);
    R42(c2, d2, e2, a2, b2, w[2], 12);
    R41(b1, c1, d1, e1, a1, w[15], 6);
    R42(b2, c2, d2, e2, a2, w[13], 9);
    R41(a1, b1, c1, d1, e1, w[14], 8);
    R42(a2, b2, c2, d2, e2, w[9], 12);
    R41(e1, a1, b1, c1, d1, w[5], 6);
    R42(e2, a2, b2, c2, d2, w[7], 5);
    R41(d1, e1, a1, b1, c1, w[6], 5);
    R42(d2, e2, a2, b2, c2, w[10], 15);
    R41(c1, d1, e1, a1, b1, w[2], 12);
    R42(c2, d2, e2, a2, b2, w[14], 8);

    R51(b1, c1, d1, e1, a1, w[4], 9);
    R52(b2, c2, d2, e2, a2, w[12], 8);
    R51(a1, b1, c1, d1, e1, w[0], 15);
    R52(a2, b2, c2, d2, e2, w[15], 5);
    R51(e1, a1, b1, c1, d1, w[5], 5);
    R52(e2, a2, b2, c2, d2, w[10], 12);
    R51(d1, e1, a1, b1, c1, w[9], 11);
    R52(d2, e2, a2, b2, c2, w[4], 9);
    R51(c1, d1, e1, a1, b1, w[7], 6);
    R52(c2, d2, e2, a2, b2, w[1], 12);
    R51(b1, c1, d1, e1, a1, w[12], 8);
    R52(b2, c2, d2, e2, a2, w[5], 5);
    R51(a1, b1, c1, d1, e1, w[2], 13);
    R52(a2, b2, c2, d2, e2, w[8], 14);
    R51(e1, a1, b1, c1, d1, w[10], 12);
    R52(e2, a2, b2, c2, d2, w[7], 6);
    R51(d1, e1, a1, b1, c1, w[14], 5);
    R52(d2, e2, a2, b2, c2, w[6], 8);
    R51(c1, d1, e1, a1, b1, w[1], 12);
    R52(c2, d2, e2, a2, b2, w[2], 13);
    R51(b1, c1, d1, e1, a1, w[3], 13);
    R52(b2, c2, d2, e2, a2, w[13], 6);
    R51(a1, b1, c1, d1, e1, w[8], 14);
    R52(a2, b2, c2, d2, e2, w[14], 5);
    R51(e1, a1, b1, c1, d1, w[11], 11);
    R52(e2, a2, b2, c2, d2, w[0], 15);
    R51(d1, e1, a1, b1, c1, w[6], 8);
    R52(d2, e2, a2, b2, c2, w[3], 13);
    R51(c1, d1, e1, a1, b1, w[15], 5);
    R52(c2, d2, e2, a2, b2, w[9], 11);
    R51(b1, c1, d1, e1, a1, w[13], 6);
    R52(b2, c2, d2, e2, a2, w[11], 11);
    
    // Combine results and update state
    __m256i t = s[0];
    s[0] = add3(s[1], c1, d2);
    s[1] = add3(s[2], d1, e2);
    s[2] = add3(s[3], e1, a2);
    s[3] = add3(s[4], a1, b2);
    s[4] = add3(t, b1, c2);
}

#ifdef WIN64
#define DEPACK(d, i)                                   \
    ((uint32_t *)d)[0] = _mm256_extract_epi32(s[0], i); \
    ((uint32_t *)d)[1] = _mm256_extract_epi32(s[1], i); \
    ((uint32_t *)d)[2] = _mm256_extract_epi32(s[2], i); \
    ((uint32_t *)d)[3] = _mm256_extract_epi32(s[3], i); \
    ((uint32_t *)d)[4] = _mm256_extract_epi32(s[4], i);
#else
#define DEPACK(d, i)                                  \
    ((uint32_t *)d)[0] = ((uint32_t *)&s[0])[i];      \
    ((uint32_t *)d)[1] = ((uint32_t *)&s[1])[i];      \
    ((uint32_t *)d)[2] = ((uint32_t *)&s[2])[i];      \
    ((uint32_t *)d)[3] = ((uint32_t *)&s[3])[i];      \
    ((uint32_t *)d)[4] = ((uint32_t *)&s[4])[i];
#endif

static const uint64_t sizedesc_32 = 32 << 3;
static const unsigned char pad[64] = { 0x80 };

// Main function to compute Rimepd160 hash for 8 messages of 32 bytes each
void ripemd160avx2_32(
    unsigned char *i0, unsigned char *i1,
    unsigned char *i2, unsigned char *i3,
    unsigned char *i4, unsigned char *i5,
    unsigned char *i6, unsigned char *i7,
    unsigned char *d0, unsigned char *d1,
    unsigned char *d2, unsigned char *d3,
    unsigned char *d4, unsigned char *d5,
    unsigned char *d6, unsigned char *d7)
{
    __m256i s[5];
    uint8_t *bs[] = { i0, i1, i2, i3, i4, i5, i6, i7 };

    // Initialize state
    ripemd160avx2::Initialize(s);

    // Add padding and length
    for (int i = 0; i < 8; ++i) {
        memcpy(bs[i] + 32, pad, 24);          
        memcpy(bs[i] + 56, &sizedesc_32, 8);  
    }

    // Process message blocks
    ripemd160avx2::Transform(s, bs);

#ifndef WIN64
    uint32_t *s0 = (uint32_t *)&s[0];
    uint32_t *s1 = (uint32_t *)&s[1];
    uint32_t *s2 = (uint32_t *)&s[2];
    uint32_t *s3 = (uint32_t *)&s[3];
    uint32_t *s4 = (uint32_t *)&s[4];
#endif

    // Unpack the hash values to the output buffers
    DEPACK(d0, 7);
    DEPACK(d1, 6);
    DEPACK(d2, 5);
    DEPACK(d3, 4);
    DEPACK(d4, 3);
    DEPACK(d5, 2);
    DEPACK(d6, 1);
    DEPACK(d7, 0);
}

}  // namespace ripemd160avx2
