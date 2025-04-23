#include "sha256_avx2.h"
#include <immintrin.h>
#include <string.h>
#include <stdint.h>

namespace _sha256avx2 {

#ifdef _MSC_VER
#define ALIGN32 __declspec(align(32))
#else
#define ALIGN32 __attribute__((aligned(32)))
#endif

// Initialize SHA-256 state with initial hash values
void Initialize(__m256i* s) {
    const uint32_t init[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    for (int i = 0; i < 8; ++i) {
        s[i] = _mm256_set1_epi32(init[i]);
    }
}

// SHA-256 macroses with avx2 intrinsics
#define Maj(x, y, z) _mm256_or_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_or_si256(x, y)))
#define Ch(x, y, z)  _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z))
#define ROR(x, n)    _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - n))
#define SHR(x, n)    _mm256_srli_epi32(x, n)

#define S0(x) (_mm256_xor_si256(ROR(x, 2), _mm256_xor_si256(ROR(x, 13), ROR(x, 22))))
#define S1(x) (_mm256_xor_si256(ROR(x, 6), _mm256_xor_si256(ROR(x, 11), ROR(x, 25))))
#define s0(x) (_mm256_xor_si256(ROR(x, 7), _mm256_xor_si256(ROR(x, 18), SHR(x, 3))))
#define s1(x) (_mm256_xor_si256(ROR(x, 17), _mm256_xor_si256(ROR(x, 19), SHR(x, 10))))

#define Round(a, b, c, d, e, f, g, h, Kt, Wt)                                    \
    T1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(h, S1(e)), Ch(e, f, g)), Kt), Wt); \
    T2 = _mm256_add_epi32(S0(a), Maj(a, b, c));                                  \
    h = g;                                                                       \
    g = f;                                                                       \
    f = e;                                                                       \
    e = _mm256_add_epi32(d, T1);                                                 \
    d = c;                                                                       \
    c = b;                                                                       \
    b = a;                                                                       \
    a = _mm256_add_epi32(T1, T2);

void Transform(__m256i* state, const uint8_t* data[8]) {
    __m256i a, b, c, d, e, f, g, h;
    __m256i W[64];
    __m256i T1, T2;

    // Load state into local variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    // Prepare message schedule W[0..15]
    for (int t = 0; t < 16; ++t) {
        uint32_t wt[8];
        for (int i = 0; i < 8; ++i) {
            const uint8_t* ptr = data[i] + t * 4;
            wt[i] = ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) | ((uint32_t)ptr[2] << 8) | ((uint32_t)ptr[3]);
        }
        W[t] = _mm256_setr_epi32(wt[0], wt[1], wt[2], wt[3], wt[4], wt[5], wt[6], wt[7]);
    }

    for (int t = 16; t < 64; ++t) {
        W[t] = _mm256_add_epi32(
                    _mm256_add_epi32(s1(W[t - 2]), W[t - 7]),
                    _mm256_add_epi32(s0(W[t - 15]), W[t - 16]));
    }

    // Constants
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Main loop of SHA-256
    for (int t = 0; t < 64; ++t) {
        __m256i Kt = _mm256_set1_epi32(K[t]);
        Round(a, b, c, d, e, f, g, h, Kt, W[t]);
    }

    state[0] = _mm256_add_epi32(state[0], a);
    state[1] = _mm256_add_epi32(state[1], b);
    state[2] = _mm256_add_epi32(state[2], c);
    state[3] = _mm256_add_epi32(state[3], d);
    state[4] = _mm256_add_epi32(state[4], e);
    state[5] = _mm256_add_epi32(state[5], f);
    state[6] = _mm256_add_epi32(state[6], g);
    state[7] = _mm256_add_epi32(state[7], h);
}

} // namespace _sha256avx2

void sha256avx2_8B(
    const uint8_t* data0, const uint8_t* data1, const uint8_t* data2, const uint8_t* data3,
    const uint8_t* data4, const uint8_t* data5, const uint8_t* data6, const uint8_t* data7,
    unsigned char* hash0, unsigned char* hash1, unsigned char* hash2, unsigned char* hash3,
    unsigned char* hash4, unsigned char* hash5, unsigned char* hash6, unsigned char* hash7) {

    __m256i state[8];

    // Initialize the state with the initial hash values
    _sha256avx2::Initialize(state);

    const uint8_t* data[8] = { data0, data1, data2, data3, data4, data5, data6, data7 };

    // Process the data blocks
    _sha256avx2::Transform(state, data);

    // Store the resulting state
    ALIGN32 uint32_t digest[8][8]; // digest[state_index][element_index]

    for (int i = 0; i < 8; ++i) {
        _mm256_store_si256((__m256i*)digest[i], state[i]);
    }

    unsigned char* hashArray[8] = { hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7 };

    // Extract the hash values and copy to output buffers
    for (int i = 0; i < 8; ++i) { 
        unsigned char* hash = hashArray[i];
        for (int j = 0; j < 8; ++j) { 
            uint32_t word = digest[j][i];
#ifdef _MSC_VER
            word = _byteswap_ulong(word);
#else
            word = __builtin_bswap32(word);
#endif
            memcpy(hash + j * 4, &word, 4);
        }
    }
}

