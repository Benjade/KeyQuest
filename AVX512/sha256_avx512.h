#ifndef SHA256_AVX512_H
#define SHA256_AVX512_H

#include <cstdint>

extern "C" void sha256_avx512_16B(
    const uint8_t* d0,  const uint8_t* d1,  const uint8_t* d2,  const uint8_t* d3,
    const uint8_t* d4,  const uint8_t* d5,  const uint8_t* d6,  const uint8_t* d7,
    const uint8_t* d8,  const uint8_t* d9,  const uint8_t* d10, const uint8_t* d11,
    const uint8_t* d12, const uint8_t* d13, const uint8_t* d14, const uint8_t* d15,
    unsigned char* h0,  unsigned char* h1,  unsigned char* h2,  unsigned char* h3,
    unsigned char* h4,  unsigned char* h5,  unsigned char* h6,  unsigned char* h7,
    unsigned char* h8,  unsigned char* h9,  unsigned char* h10, unsigned char* h11,
    unsigned char* h12, unsigned char* h13, unsigned char* h14, unsigned char* h15
);

#endif
