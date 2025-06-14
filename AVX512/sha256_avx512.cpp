#include "sha256_avx512.h"
#include <immintrin.h>
#include <stdint.h>
#include <cstring>

#ifdef _MSC_VER
#define ALIGN64 __declspec(align(64))
#else
#define ALIGN64 alignas(64)
#endif

#define ROR(x,n) _mm512_or_epi32(_mm512_srli_epi32((x),(n)), _mm512_slli_epi32((x),(32-(n))))
#define SHR(x,n) _mm512_srli_epi32((x),(n))
#define Ch(x,y,z)  _mm512_xor_epi32(_mm512_and_epi32((x),(y)), _mm512_andnot_si512((x),(z)))
#define Maj(x,y,z) _mm512_or_epi32(_mm512_and_epi32((x),(y)), _mm512_and_epi32((z),_mm512_or_epi32((x),(y))))
#define S0(x) _mm512_xor_epi32(ROR((x),2),  _mm512_xor_epi32(ROR((x),13), ROR((x),22)))
#define S1(x) _mm512_xor_epi32(ROR((x),6),  _mm512_xor_epi32(ROR((x),11), ROR((x),25)))
#define s0(x) _mm512_xor_epi32(ROR((x),7),  _mm512_xor_epi32(ROR((x),18), SHR((x),3)))
#define s1(x) _mm512_xor_epi32(ROR((x),17), _mm512_xor_epi32(ROR((x),19), SHR((x),10)))

static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
  0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
  0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
  0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline void Initialize(__m512i* s) {
  static const uint32_t iv[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  };
  for (int i = 0; i < 8; i++) {
    s[i] = _mm512_set1_epi32(iv[i]);
  }
}

#define ROUND(a,b,c,d,e,f,g,h,Kt,Wt,T1,T2) \
  T1 = _mm512_add_epi32(_mm512_add_epi32(_mm512_add_epi32(_mm512_add_epi32(h,S1(e)),Ch(e,f,g)),Kt),Wt); \
  T2 = _mm512_add_epi32(S0(a),Maj(a,b,c)); \
  h = g; g = f; f = e; e = _mm512_add_epi32(d,T1); \
  d = c; c = b; b = a; a = _mm512_add_epi32(T1,T2);

static void Transform(__m512i* state, const uint8_t* data[16]) {
  __m512i a = state[0], b = state[1], c = state[2], d = state[3];
  __m512i e = state[4], f = state[5], g = state[6], h = state[7];
  __m512i W[64], T1, T2;

  for (int t = 0; t < 16; t++) {
    uint32_t tmp[16];
    for (int i = 0; i < 16; i++) {
      const uint8_t* p = data[i] + t*4;
      tmp[i] = (uint32_t(p[0]) << 24) |
               (uint32_t(p[1]) << 16) |
               (uint32_t(p[2]) <<  8) |
               (uint32_t(p[3]) <<  0);
    }
    W[t] = _mm512_setr_epi32(
      tmp[0], tmp[1], tmp[2], tmp[3],
      tmp[4], tmp[5], tmp[6], tmp[7],
      tmp[8], tmp[9], tmp[10],tmp[11],
      tmp[12],tmp[13],tmp[14],tmp[15]
    );
  }

  for (int t = 16; t < 64; t++) {
    W[t] = _mm512_add_epi32(
             _mm512_add_epi32(s1(W[t-2]), W[t-7]),
             _mm512_add_epi32(s0(W[t-15]),W[t-16])
           );
  }

  for (int t = 0; t < 64; t++) {
    __m512i Kt = _mm512_set1_epi32(K[t]);
    ROUND(a,b,c,d,e,f,g,h,Kt,W[t],T1,T2);
  }

  state[0] = _mm512_add_epi32(state[0], a);
  state[1] = _mm512_add_epi32(state[1], b);
  state[2] = _mm512_add_epi32(state[2], c);
  state[3] = _mm512_add_epi32(state[3], d);
  state[4] = _mm512_add_epi32(state[4], e);
  state[5] = _mm512_add_epi32(state[5], f);
  state[6] = _mm512_add_epi32(state[6], g);
  state[7] = _mm512_add_epi32(state[7], h);
}

extern "C" void sha256_avx512_16B(
  const uint8_t* d0,  const uint8_t* d1,  const uint8_t* d2,  const uint8_t* d3,
  const uint8_t* d4,  const uint8_t* d5,  const uint8_t* d6,  const uint8_t* d7,
  const uint8_t* d8,  const uint8_t* d9,  const uint8_t* d10, const uint8_t* d11,
  const uint8_t* d12, const uint8_t* d13, const uint8_t* d14, const uint8_t* d15,
  unsigned char* h0,  unsigned char* h1,  unsigned char* h2,  unsigned char* h3,
  unsigned char* h4,  unsigned char* h5,  unsigned char* h6,  unsigned char* h7,
  unsigned char* h8,  unsigned char* h9,  unsigned char* h10, unsigned char* h11,
  unsigned char* h12, unsigned char* h13, unsigned char* h14, unsigned char* h15
) {
  __m512i s[8];
  Initialize(s);
  const uint8_t* data[16] = {
    d0,d1,d2,d3,d4,d5,d6,d7,
    d8,d9,d10,d11,d12,d13,d14,d15
  };
  Transform(s, data);

  ALIGN64 uint32_t tmp[8][16];
  for (int i = 0; i < 8; i++) {
    _mm512_store_si512((__m512i*)tmp[i], s[i]);
  }

  unsigned char* H[16] = {
    h0,h1,h2,h3,h4,h5,h6,h7,
    h8,h9,h10,h11,h12,h13,h14,h15
  };

  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 8; j++) {
      uint32_t w = tmp[j][i];
#ifdef _MSC_VER
      w = _byteswap_ulong(w);
#else
      w = __builtin_bswap32(w);
#endif
      std::memcpy(H[i] + j*4, &w, 4);
    }
  }
}
