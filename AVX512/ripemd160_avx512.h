#ifndef RIPEMD160_AVX512_H
#define RIPEMD160_AVX512_H

#include <immintrin.h>
#include <cstdint>

namespace ripemd160avx512 {

void Initialize(__m512i* s);

void Transform(__m512i* state, uint8_t* blocks[16]);

void ripemd160avx512_32(
    unsigned char* i0,   unsigned char* i1,   unsigned char* i2,   unsigned char* i3,
    unsigned char* i4,   unsigned char* i5,   unsigned char* i6,   unsigned char* i7,
    unsigned char* i8,   unsigned char* i9,   unsigned char* i10,  unsigned char* i11,
    unsigned char* i12,  unsigned char* i13,  unsigned char* i14,  unsigned char* i15,
    unsigned char* d0,   unsigned char* d1,   unsigned char* d2,   unsigned char* d3,
    unsigned char* d4,   unsigned char* d5,   unsigned char* d6,   unsigned char* d7,
    unsigned char* d8,   unsigned char* d9,   unsigned char* d10,  unsigned char* d11,
    unsigned char* d12,  unsigned char* d13,  unsigned char* d14,  unsigned char* d15
);

}  // namespace ripemd160avx512

#endif  // RIPEMD160_AVX512_H
