/*
  ------------------------------------------------------------------------------
  KeyQuest V1.2 by Benjade https://github.com/Benjade

  DISCLAIMER:
  This program is created exclusively for tackling challenging cryptographic puzzles,
  such as the 1000BTC Bitcoin Challenge (see https://privatekeys.pw/puzzles/bitcoin-puzzle-tx). 
  Illicit usage is expressly prohibited, and the author assumes no liability 
  for any misuse by third parties.
  ------------------------------------------------------------------------------
  
  Install
  make clean && make -j$(nproc)

  START using one of the following optimization (optional):
  export OMP_NUM_THREADS=$(nproc) OMP_PROC_BIND=spread OMP_PLACES=cores ./KeyQuest  # TIP: Bind each thread to a unique core to maximize cache reuse and predictable performance (Real threads).
  export OMP_NUM_THREADS=$(( $(nproc) * 2 )) OMP_PROC_BIND=spread OMP_PLACES=cores ./KeyQuest  # TIP: Spread threads evenly across cores to balance load when oversubscribing (Virtual threads).
  unset OMP_NUM_THREADS OMP_PROC_BIND OMP_PLACES OMP_DYNAMIC  # TIP: Remove custom OpenMP settings to revert to default thread scheduling.

  Fast test using Address: 
  19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR Range: 349b84b6431a000000:349b84b6431affffff Suffix: 6
  -------------------------------------------------------------------------------
*/

#include <immintrin.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <chrono>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <array>
#include <utility>
#include <cstdio>
#include <numeric>
#include <random>
#include <omp.h>
#include <cctype>
#include <thread>
#include <atomic>
#include <mutex>
#include <cmath>
#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>

// Local headers
#include "p2pkh_decoder.h"
#include "sha256_avx2.h"
#include "ripemd160_avx2.h"
#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"

// =====================
// Global configurable settings
// =====================
static constexpr uint32_t SUFFIX_PER_PREFIX = 1; // x suffix tested per prefix
static std::string MAIL_FROM      = "KeyQuest";
static std::string MAIL_TO        = "your@email.com";
static std::string MAIL_SUBJECT   = "🚨ALERT🚨 FOUND MATCH!";
static std::string MAIL_PROGRAM   = "msmtp -t"; // or "/usr/sbin/sendmail" as needed

// === Configurable ANSI Colors ===
static std::string COLOR_FRAME    = "\033[38;5;208m"; // outline / frame (orange)
static std::string COLOR_LABEL    = "\033[38;5;221m"; // labels (yellow)
static std::string COLOR_VALUE    = "\033[1;37m";     // values ​​/ details (bright white)
static std::string COLOR_RESET    = "\033[0m";        // reset

// -----------------------------------------------------------------------------
// Function to get server IP via api.ipify.org
// -----------------------------------------------------------------------------
static std::string getPublicIP() {
    std::string ip;
    FILE* pipe = popen("curl -s https://api.ipify.org", "r");
    if (!pipe) return "unknown";
    char buf[64];
    if (fgets(buf, sizeof(buf), pipe)) {
        ip = buf;
        if (!ip.empty() && ip.back() == '\n')
            ip.pop_back();
    }
    pclose(pipe);
    return ip;
}

// -----------------------------------------------------------------------------
// Function to convert __uint128_t to std::string (base 10)
// -----------------------------------------------------------------------------
std::string uint128ToString(__uint128_t value) {
    if (value == 0)
        return "0";
    std::string result;
    while (value > 0) {
        int digit = value % 10;
        result.push_back('0' + digit);
        value /= 10;
    }
    std::reverse(result.begin(), result.end());
    return result;
}

// -----------------------------------------------------------------------------
// Function to insert commas in a large number represented as a string
// -----------------------------------------------------------------------------
std::string formatWithCommas128(const std::string &s) {
    std::string result = s;
    int pos = result.size() - 3;
    while (pos > 0) {
        result.insert(pos, ",");
        pos -= 3;
    }
    return result;
}

// =====================
// Minimal SHA256 and Base58 functions
// =====================

typedef unsigned char BYTE;
typedef unsigned int  WORD;
#define SHA256_BLOCK_SIZE 32

// SHA256 macros
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const WORD k[64] = {
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

typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;

static inline __attribute__((always_inline))
void sha256_transform(SHA256_CTX *ctx, const BYTE data[]) {
    WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + SIG0(m[i-15]) + m[i-7] + m[i-16];
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static inline __attribute__((always_inline))
void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen  = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, BYTE hash[]) {
    WORD i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    for (int j = 0; j < 8; ++j) {
        ctx->data[63 - j] = (ctx->bitlen >> (j*8)) & 0xFF;
    }
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i*8)) & 0xff;
        hash[i+4]    = (ctx->state[1] >> (24 - i*8)) & 0xff;
        hash[i+8]    = (ctx->state[2] >> (24 - i*8)) & 0xff;
        hash[i+12]   = (ctx->state[3] >> (24 - i*8)) & 0xff;
        hash[i+16]   = (ctx->state[4] >> (24 - i*8)) & 0xff;
        hash[i+20]   = (ctx->state[5] >> (24 - i*8)) & 0xff;
        hash[i+24]   = (ctx->state[6] >> (24 - i*8)) & 0xff;
        hash[i+28]   = (ctx->state[7] >> (24 - i*8)) & 0xff;
    }
}

static std::vector<uint8_t> simpleSHA256(const std::vector<uint8_t>& data) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data.data(), data.size());
    BYTE hash[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, hash);
    return std::vector<uint8_t>(hash, hash + SHA256_BLOCK_SIZE);
}

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static std::string base58Encode(const std::vector<uint8_t>& input) {
    int zeros = 0;
    while (zeros < (int)input.size() && input[zeros] == 0) zeros++;
    std::vector<uint8_t> b58((input.size()-zeros)*138/100+1);
    size_t length = 0;
    for (int i = zeros; i < (int)input.size(); ++i) {
        int carry = input[i];
        size_t j = 0;
        for (auto it = b58.rbegin(); (carry != 0 || j < length) && it != b58.rend(); ++it, ++j) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        length = j;
    }
    auto it = b58.begin() + (b58.size() - length);
    std::string result;
    result.reserve(zeros + length);
    result.assign(zeros, '1');
    while (it != b58.end()) {
        result.push_back(pszBase58[*it]);
        ++it;
    }
    return result;
}

static std::string encodeAddress(const std::vector<uint8_t>& hash160) {
    std::vector<uint8_t> v;
    v.push_back(0x00);
    v.insert(v.end(), hash160.begin(), hash160.end());
    auto h1 = simpleSHA256(v);
    auto h2 = simpleSHA256(h1);
    v.insert(v.end(), h2.begin(), h2.begin() + 4);
    return base58Encode(v);
}

// =====================
// End of SHA256/Base58 functions
// =====================

// -----------------------------------------------------------------------------
// Global constants/structures
// -----------------------------------------------------------------------------
static int g_pointsBatchSize = 512;
static constexpr int HASH_BATCH_SIZE   = 8;

struct Config {
    bool loaded        = false;
    bool encryption    = false;
    int numThreads     = 1;
    std::string address;
    std::string range;
    int randomHexCount = 0;
};

static const char* kConfigFile = "config.txt";

// Encryption
static bool        g_encryptResult = false;
static std::string g_passphrase    = "";

static bool g_fullRandomMode = false;
static bool                            g_hybridMode = true;
static std::atomic<unsigned long long> g_prefixesTested(0ULL);

static bool g_showThreadProgress = true;
static std::vector<std::string> g_threadKeys;
static std::mutex g_threadKeysMutex;
static std::atomic<unsigned long long> g_comparedCount(0ULL);
static std::atomic<bool>               g_stopStats(false);

static std::atomic<bool> g_found(false);
static long double g_totalCombosLD = 0.0L;
static std::string g_foundPriv, g_foundPub, g_foundWIF;
static double g_finalElapsed=0.0, g_finalSpeed=0.0;

static std::vector<unsigned long long> g_threadRestarts;
static bool g_altBufferUsed_display=false;

// -----------------------------------------------------------------------------
// Helper: remove ANSI
// -----------------------------------------------------------------------------
static inline __attribute__((always_inline))
std::string removeANSI(const std::string &s) {
    bool inEscape=false;
    std::ostringstream out;
    for(char c:s){
        if(!inEscape&&c=='\033'){inEscape=true;continue;}
        if(inEscape&&c=='m'){inEscape=false;continue;}
        if(!inEscape) out<<c;
    }
    return out.str();
}

// -----------------------------------------------------------------------------
// Formatting functions
// -----------------------------------------------------------------------------
static inline __attribute__((always_inline))
std::string padHex(const std::string &s, int width){
    return s.size()>= (size_t)width? s:std::string(width-s.size(),'0')+s;
}

static inline __attribute__((always_inline))
std::string formatWithCommas(unsigned long long n){
    auto s=std::to_string(n);
    int pos=(int)s.size()-3;
    while(pos>0){s.insert(pos, ",");pos-=3;}
    return s;
}

static inline __attribute__((always_inline))
std::string formatElapsedTime(double sec){
    int hrs=(int)sec/3600;
    int mins=((int)sec%3600)/60;
    int secs=(int)sec%60;
    std::ostringstream oss;
    oss<<std::setw(2)<<std::setfill('0')<<hrs<<":"
       <<std::setw(2)<<std::setfill('0')<<mins<<":"
       <<std::setw(2)<<std::setfill('0')<<secs;
    return oss.str();
}

// -----------------------------------------------------------------------------
// BigNum conversion
// -----------------------------------------------------------------------------
static std::vector<uint64_t> hexToBigNum(const std::string &hex){
    std::vector<uint64_t> bn;
    size_t len=hex.size();
    bn.reserve((len+15)/16);
    for(size_t i=0;i<len;i+=16){
        size_t st=len>=16+i?len-16-i:0;
        size_t ln=len>=16+i?16:len-i;
        bn.push_back(std::stoull(hex.substr(st,ln),nullptr,16));
    }
    if(bn.empty()) bn.push_back(0ULL);
    return bn;
}

static std::string bigNumToHex(const std::vector<uint64_t> &bn){
    if(bn.empty()) return "0";
    std::ostringstream oss;
    oss<<std::hex<<std::nouppercase;
    bool first=true;
    for(auto it=bn.rbegin();it!=bn.rend();++it){
        if(first){oss<<*it;first=false;}
        else oss<<std::setw(16)<<std::setfill('0')<<*it;
    }
    return oss.str();
}

static std::vector<uint64_t> singleElementVector(uint64_t v){
    return {v};
}

static std::vector<uint64_t> bigNumAdd(const std::vector<uint64_t> &a,
                                       const std::vector<uint64_t> &b){
    std::vector<uint64_t> sum;
    sum.reserve(std::max(a.size(),b.size())+1);
    uint64_t carry=0;
    size_t sz=std::max(a.size(),b.size());
    for(size_t i=0;i<sz;++i){
        uint64_t x=i<a.size()?a[i]:0;
        uint64_t y=i<b.size()?b[i]:0;
        __uint128_t s=(__uint128_t)x+(__uint128_t)y+carry;
        carry=(uint64_t)(s>>64);
        sum.push_back((uint64_t)s);
    }
    if(carry) sum.push_back(carry);
    return sum;
}

static std::vector<uint64_t> bigNumSubtract(const std::vector<uint64_t> &a,
                                            const std::vector<uint64_t> &b){
    std::vector<uint64_t> diff=a;
    uint64_t borrow=0;
    for(size_t i=0;i<b.size();++i){
        uint64_t sub=b[i];
        if(diff[i]<sub+borrow){
            diff[i]=diff[i]+(~0ULL)-sub-borrow+1; borrow=1;
        } else {
            diff[i]-=(sub+borrow); borrow=0;
        }
    }
    for(size_t i=b.size();i<diff.size()&&borrow;++i){
        if(diff[i]==0) diff[i]=~0ULL;
        else{diff[i]--; borrow=0;}
    }
    while(!diff.empty()&&diff.back()==0) diff.pop_back();
    if(diff.empty()) diff.push_back(0ULL);
    return diff;
}

static std::pair<std::vector<uint64_t>,uint64_t>
bigNumDivide(const std::vector<uint64_t> &a,uint64_t divisor){
    std::vector<uint64_t> q(a.size(),0);
    uint64_t rem=0;
    for(int i=(int)a.size()-1;i>=0;--i){
        __uint128_t tmp=((__uint128_t)rem<<64)|a[i];
        q[i]=(uint64_t)(tmp/divisor);
        rem=(uint64_t)(tmp%divisor);
    }
    while(!q.empty()&&q.back()==0) q.pop_back();
    if(q.empty()) q.push_back(0ULL);
    return {q,rem};
}

static long double hexStrToLongDouble(const std::string &hex){
    long double r=0.0L;
    for(char c:hex){
        r*=16.0L;
        if(c>='0'&&c<='9') r+=c-'0';
        else if(c>='a'&&c<='f') r+=c-'a'+10;
        else if(c>='A'&&c<='F') r+=c-'A'+10;
    }
    return r;
}

// ----------------------------------------------------------------------------
// Compare two vectors “big-ints” little-endian
//   –1 si a<b, 0 si égal, +1 si a>b
static int bigNumCompare(const std::vector<uint64_t>& a,
                         const std::vector<uint64_t>& b) {
  int La = (int)a.size(), Lb = (int)b.size(), L = std::max(La,Lb);
  for(int i=L-1; i>=0; --i) {
    uint64_t ai = (i<La? a[i]:0), bi = (i<Lb? b[i]:0);
    if (ai<bi) return -1;
    if (ai>bi) return +1;
  }
  return 0;
}

static std::vector<uint64_t> bigNumRandom(const std::vector<uint64_t>& sizeBN,
                                          int totalBits) {
  thread_local std::mt19937_64 rng(std::random_device{}());
  size_t L = sizeBN.size();
  unsigned topBits = totalBits % 64;
  uint64_t topMask  = topBits ? ((uint64_t(1)<<topBits)-1) : ~uint64_t(0);
  std::vector<uint64_t> rnd(L);
  do {
    for(size_t i=0;i<L;++i) rnd[i] = rng();
    rnd[L-1] &= topMask;
  } while(bigNumCompare(rnd, sizeBN) >= 0);
  return rnd;
}

// -----------------------------------------------------------------------------
// ECC helper functions
// -----------------------------------------------------------------------------
static inline __attribute__((always_inline))
bool isEven(const Int &val){ return ((Int&)val).IsEven(); }

static inline __attribute__((always_inline))
std::string intToHex(const Int &val){
    Int t; t.Set((Int*)&val);
    return t.GetBase16();
}

static std::string pointToCompressedHex(const Point &p){
    Int tx; tx.Set((Int*)&p.x);
    auto hx=tx.GetBase16();
    if(hx.size()<64) hx=std::string(64-hx.size(),'0')+hx;
    return (isEven(p.y)?"02":"03")+hx;
}

static void pointToCompressedBin(const Point &p,uint8_t out[33]){
    out[0]=isEven(p.y)?0x02:0x03;
    Int tx; tx.Set((Int*)&p.x);
    for(int i=0;i<32;++i) out[1+i]=(uint8_t)tx.GetByte(31-i);
}

// -----------------------------------------------------------------------------
// Thread-local MT19937_64 PRNG and hex LUT for suffix generation
// -----------------------------------------------------------------------------
thread_local std::mt19937_64 tl_rng(std::random_device{}());
static char hexLUT[16] = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
};
static inline std::string fastRandomHex(int n) {
    std::string s(n, '0');
    for(int i=0;i<n;i++){
        uint64_t v = tl_rng() & 0xFULL;
        s[i] = hexLUT[v];
    }
    return s;
}

// -----------------------------------------------------------------------------
// p2pkh in batch
// -----------------------------------------------------------------------------
using Align64 = std::array<uint8_t, 64>;
using Align32 = std::array<uint8_t, 32>;

static inline __attribute__((always_inline))
void prepareShaBlock(const uint8_t* dataSrc, size_t dataLen, uint8_t* outBlock) {
    std::fill_n(outBlock, 64, 0);
    memcpy(outBlock, dataSrc, dataLen);
    outBlock[dataLen] = 0x80;
    uint32_t bitLen = (uint32_t)(dataLen * 8);
    outBlock[60] = (bitLen >> 24) & 0xFF;
    outBlock[61] = (bitLen >> 16) & 0xFF;
    outBlock[62] = (bitLen >> 8 ) & 0xFF;
    outBlock[63] =  bitLen        & 0xFF;
}

static inline __attribute__((always_inline))
void prepareRipemdBlock(const uint8_t* dataSrc, uint8_t* outBlock) {
    std::fill_n(outBlock, 64, 0);
    memcpy(outBlock, dataSrc, 32);
    outBlock[32] = 0x80;
    uint32_t bitLen = 256;
    outBlock[60] = (bitLen >> 24) & 0xFF;
    outBlock[61] = (bitLen >> 16) & 0xFF;
    outBlock[62] = (bitLen >> 8 ) & 0xFF;
    outBlock[63] =  bitLen        & 0xFF;
}

static void computeHash160BatchBinSingle(int numKeys,
                                         uint8_t pubKeys[][33],
                                         uint8_t hashRes[][20]) {
    std::array<Align64, HASH_BATCH_SIZE> shaIn;
    std::array<Align32, HASH_BATCH_SIZE> shaOut;
    std::array<Align64, HASH_BATCH_SIZE> ripemdIn;
    std::array<std::array<uint8_t,20>, HASH_BATCH_SIZE> ripemdOut;

    int totalB = (numKeys + (HASH_BATCH_SIZE - 1)) / HASH_BATCH_SIZE;
    for(int b=0; b<totalB; ++b){
        int bCount = std::min(HASH_BATCH_SIZE, numKeys - b * HASH_BATCH_SIZE);
        for(int i=0; i<bCount; ++i){
            int idx = b * HASH_BATCH_SIZE + i;
            prepareShaBlock(pubKeys[idx], 33, shaIn[i].data());
        }
        for(int i=bCount; i<HASH_BATCH_SIZE; ++i)
            memcpy(shaIn[i].data(), shaIn[0].data(), 64);

        const uint8_t* inPtr[HASH_BATCH_SIZE];
        uint8_t* outPtr[HASH_BATCH_SIZE];
        for(int i=0; i<HASH_BATCH_SIZE; ++i){
            inPtr[i] = shaIn[i].data();
            outPtr[i] = shaOut[i].data();
        }
        sha256avx2_8B(inPtr[0],inPtr[1],inPtr[2],inPtr[3],
                      inPtr[4],inPtr[5],inPtr[6],inPtr[7],
                      outPtr[0],outPtr[1],outPtr[2],outPtr[3],
                      outPtr[4],outPtr[5],outPtr[6],outPtr[7]);

        for(int i=0; i<bCount; ++i)
            prepareRipemdBlock(shaOut[i].data(), ripemdIn[i].data());
        for(int i=bCount; i<HASH_BATCH_SIZE; ++i)
            memcpy(ripemdIn[i].data(), ripemdIn[0].data(), 64);

        for(int i=0; i<HASH_BATCH_SIZE; ++i){
            inPtr[i] = ripemdIn[i].data();
            outPtr[i] = reinterpret_cast<uint8_t*>(ripemdOut[i].data());
        }
        ripemd160avx2::ripemd160avx2_32(
            (unsigned char*)inPtr[0],(unsigned char*)inPtr[1],
            (unsigned char*)inPtr[2],(unsigned char*)inPtr[3],
            (unsigned char*)inPtr[4],(unsigned char*)inPtr[5],
            (unsigned char*)inPtr[6],(unsigned char*)inPtr[7],
            outPtr[0],outPtr[1],outPtr[2],outPtr[3],
            outPtr[4],outPtr[5],outPtr[6],outPtr[7]
        );

        for(int i=0; i<bCount; ++i){
            int idx = b * HASH_BATCH_SIZE + i;
            memcpy(hashRes[idx], ripemdOut[i].data(), 20);
        }
    }
}

// -----------------------------------------------------------------------------
// Email sending function
// -----------------------------------------------------------------------------
static void sendMatchEmail(const std::string &priv,
                           const std::string &pub,
                           const std::string &wif,
                           const std::string &addr,
                           unsigned long long totalChecked,
                           const std::string &elapsedTime,
                           double speed,
                           double pct,
                           const std::string &ip)
{
    std::ofstream f("match_email.html");
    if (!f) return;

    f <<
"From: "   << MAIL_FROM   << "\n"
"To: "     << MAIL_TO     << "\n"
"Subject: "<< MAIL_SUBJECT<< "\n"
"X-Priority: 1 (Highest)\n"
"X-MSMail-Priority: High\n"
"Importance: High\n"
"MIME-Version: 1.0\n"
"Content-Type: text/html; charset=utf-8\n"
"Content-Transfer-Encoding: 8bit\n\n"
"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
"<title>KeyQuest – Match Found</title>"
"<style>"
"body{background:#fff;font-family:Arial,sans-serif;padding:5px 0;}"
".card{max-width:960px;margin:60px auto;background:#fff;border:1px solid #ddd;"
"border-radius:12px;padding:40px;box-shadow:0 6px 14px rgba(0,0,0,.1);}"
"h1{color:#d93025;margin:0 0 30px;font-size:28px;text-align:center;}"
"table{width:100%;border-collapse:collapse;font-size:16px;}"
"th{padding:12px 0;text-align:left;color:#555;font-weight:600;width:190px;}"
"td{padding:12px 0;color:#222;}"
".val{font-family:'Courier New',monospace;background:#e7f5e9;"
"border:1px solid #c2e0c4;border-radius:4px;padding:8px 10px;"
"display:block;overflow-wrap:anywhere;}"
".small{font-size:14px;color:#666;margin-top:32px;text-align:center;}"
"</style></head><body>"
"<div class=\"card\">"
"<h1>🚀 Bitcoin Key Found! 🚀</h1>"
"<table>"
"<tr><th>Private Key</th><td><span class=\"val\">" << priv   << "</span></td></tr>"
"<tr><th>Public Key</th><td><span class=\"val\">"  << pub    << "</span></td></tr>"
"<tr><th>WIF</th><td><span class=\"val\">"         << wif    << "</span></td></tr>"
"<tr><th>Address</th><td><span class=\"val\">"     << addr   << "</span></td></tr>"
"<tr><th>Total Checked</th><td><span class=\"val\">"<< formatWithCommas(totalChecked) <<"</span></td></tr>"
"<tr><th>Elapsed Time</th><td><span class=\"val\">" << elapsedTime << "</span></td></tr>"
"<tr><th>Speed</th><td><span class=\"val\">"        << std::fixed << std::setprecision(2) << speed << " Mkeys/s</span></td></tr>"
"<tr><th>Progress</th><td><span class=\"val\">"     << std::fixed << std::setprecision(2) << pct   << "%</span></td></tr>"
"<tr><th>Server IP</th><td><span class=\"val\">"    << ip                                       << "</span></td></tr>"
"</table>"
"<p class=\"small\">Generated by KeyQuest V1.2 by <a href=\"https://github.com/Benjade\">Benjade</a></p>"
"</div></body></html>";

    f.close();

    // Sending email and capturing the return code
    int ret = system((MAIL_PROGRAM + " < match_email.html").c_str());
    if (ret != 0) {
        std::cerr << "Error sending email (code " << ret << ")\n";
    }

    // Cleaning
    remove("match_email.html");
}

// -----------------------------------------------------------------------------
// Encryption function
// -----------------------------------------------------------------------------
static void encryptSystemTxt(const std::string &pass){
    std::string cmd="openssl enc -aes-256-cbc -pbkdf2 -salt -in keyfound.txt -out keyfound.txt.enc -k \""+pass+"\"";
    if(system(cmd.c_str())==0){
        remove("keyfound.txt");
        std::cout<<"keyfound.txt.enc created.\n";
    } else {
        std::cerr<<"Error encrypting keyfound.txt\n";
    }
}

// -----------------------------------------------------------------------------
// Config load/save functions
// -----------------------------------------------------------------------------
static bool loadConfig(Config &cfg){
    std::ifstream in(kConfigFile);
    if(!in) return false;
    cfg.loaded=true;
    std::string line;
    while(std::getline(in,line)){
        if(line.empty()) continue;
        auto pos=line.find('=');
        if(pos==std::string::npos) continue;
        auto key=line.substr(0,pos);
        auto val=line.substr(pos+1);
        if(key=="encryption")     cfg.encryption=(val=="1");
        else if(key=="numThreads")cfg.numThreads=std::stoi(val);
        else if(key=="address")   cfg.address=val;
        else if(key=="range")     cfg.range=val;
        else if(key=="randomHexCount") cfg.randomHexCount=std::stoi(val);
    }
    return true;
}

static bool saveConfig(const Config &cfg){
    std::ofstream out(kConfigFile,std::ios::trunc);
    if(!out) return false;
    out<<"encryption="<<(cfg.encryption?"1":"0")<<"\n";
    out<<"numThreads="<<cfg.numThreads<<"\n";
    out<<"address="   <<cfg.address<<"\n";
    out<<"range="     <<cfg.range<<"\n";
    out<<"randomHexCount="<<cfg.randomHexCount<<"\n";
    return true;
}

// -----------------------------------------------------------------------------
// ASCII-Box display functions
// -----------------------------------------------------------------------------
static int getTerminalWidth(){
    struct winsize ws;
    if(ioctl(STDOUT_FILENO,TIOCGWINSZ,&ws)==0)
        return (ws.ws_col < 40 ? 40 : ws.ws_col);
    return 80;
}

static int ansiVisibleLen(const std::string &s){
    bool esc=false; int len=0;
    for(char c:s){
        if(!esc){
            if(c=='\033') esc=true;
            else ++len;
        } else if(c=='m') esc=false;
    }
    return len;
}

static std::string fitAnsiWidth(const std::string &in,int width){
    std::string out; out.reserve(in.size()+16);
    bool esc=false; int vis=0;
    for(char c:in){
        if(!esc){
            if(c=='\033') esc=true;
            else if(vis==width) break;
            else ++vis;
        } else if(c=='m') esc=false;
        out.push_back(c);
    }
    if(esc || (!out.empty() && out.back()!='m'))
        out += COLOR_RESET;
    return out;
}

static std::string padAnsi(std::string s,int width){
    int vis=ansiVisibleLen(s);
    if(vis>width) s=fitAnsiWidth(s,width);
    else if(vis<width) s += std::string(width-vis,' ');
    return s;
}

static void displaySummaryBox(std::ostream &os,
                              unsigned long long totalChecked,
                              double speed,
                              double elapsedTime,
                              const std::string &addr,
                              const std::string &rng,
                              unsigned long long totalRestarts,
                              double pctProgress,
                              int numThreadsUsed,
                              unsigned long long /*dupCount*/,
                              const std::string &totalCombosStr)
{
    int termWidth = getTerminalWidth();
    int inner     = std::max(40, termWidth - 2);

    os << COLOR_FRAME << "+" << std::string(inner, '-') << "+" << COLOR_RESET << "\n";

    {
        std::string title = " Statistics - KeyQuest V1.2 by Benjade ";
        int padLeft  = (inner - (int)title.size()) / 2;
        int padRight = inner - (int)title.size() - padLeft;
        std::string line = std::string(padLeft,' ')
                         + COLOR_LABEL + title + COLOR_RESET
                         + std::string(padRight,' ');
        os << COLOR_FRAME << "|" << COLOR_RESET
           << line
           << COLOR_FRAME << "|" << COLOR_RESET << "\n";
    }

    os << COLOR_FRAME << "+" << std::string(inner, '-') << "+" << COLOR_RESET << "\n";

    {
        std::ostringstream tmp;
        tmp << COLOR_LABEL << "Target: "    << COLOR_VALUE << addr           << COLOR_RESET
            << COLOR_LABEL << "    Range: " << COLOR_VALUE << rng            << COLOR_RESET
            << COLOR_LABEL << "    Mode: "  << COLOR_VALUE
            << (g_fullRandomMode ? "Random" : "Hybrid")
            << COLOR_RESET
            << COLOR_LABEL << "    Threads: "<< COLOR_VALUE << numThreadsUsed << COLOR_RESET;
        auto content = padAnsi(tmp.str(), inner);
        os << COLOR_FRAME << "|" << COLOR_RESET
           << content
           << COLOR_FRAME << "|" << COLOR_RESET << "\n";
    }

{

    std::ostringstream tmp;
    tmp << COLOR_LABEL << "Speed: "  << COLOR_VALUE
        << std::fixed << std::setprecision(2) << speed << " Mkeys/s" << COLOR_RESET
        << COLOR_LABEL << "    Total: " << COLOR_VALUE << formatWithCommas(totalChecked) << COLOR_RESET
        << COLOR_LABEL << " / "        << COLOR_VALUE << totalCombosStr
        << " (" << std::fixed << std::setprecision(10) << pctProgress << "%)" << COLOR_RESET
        << COLOR_LABEL << "    Prefix restarts: " << COLOR_VALUE << formatWithCommas(totalRestarts) << COLOR_RESET
        << COLOR_LABEL << "    Elapsed time: "    << COLOR_VALUE << formatElapsedTime(elapsedTime) << COLOR_RESET;
    auto content = padAnsi(tmp.str(), inner);
    os << COLOR_FRAME << "|" << COLOR_RESET
       << content
       << COLOR_FRAME << "|" << COLOR_RESET << "\n";
}

    os << COLOR_FRAME << "+" << std::string(inner, '-') << "+" << COLOR_RESET << "\n";
}

static void displayThreadBox(std::ostream &os, int totalThreads){
    int termW  = getTerminalWidth();
    int inner  = std::max(40, termW - 2);
    std::string border(inner, '-');

    os << COLOR_FRAME << "+" << border << "+" << COLOR_RESET << "\n";

    {
        std::string hd = " Thread Progress ";
        int padLeft  = (inner - (int)hd.size()) / 2;
        int padRight = inner - (int)hd.size() - padLeft;
        std::string line = std::string(padLeft,' ')
                         + COLOR_LABEL + hd + COLOR_RESET
                         + std::string(padRight,' ');
        os << COLOR_FRAME << "|" << COLOR_RESET
           << padAnsi(line, inner)
           << COLOR_FRAME << "|" << COLOR_RESET << "\n";
    }

    os << COLOR_FRAME << "+" << border << "+" << COLOR_RESET << "\n";

    {
        std::lock_guard<std::mutex> lock(g_threadKeysMutex);
        if(totalThreads > 256){
            static std::atomic<size_t> cur{0};
            size_t idx = cur.fetch_add(1, std::memory_order_relaxed) % totalThreads;
            std::string cell = COLOR_LABEL + "[T" + std::to_string(idx) + "]: "
                             + COLOR_RESET + COLOR_VALUE + g_threadKeys[idx] + COLOR_RESET;
            os << COLOR_FRAME << "|" << COLOR_RESET
               << padAnsi(cell, inner)
               << COLOR_FRAME << "|" << COLOR_RESET << "\n";
        } else {
            int nbCols = (totalThreads + 31) / 32;
            int colWidth = inner / nbCols;
            for(int row=0; row<32; ++row){
                std::string rowLine;
                for(int col=0; col<nbCols; ++col){
                    int idx = col*32 + row;
                    std::string cell;
                    if(idx < totalThreads){
                        cell = COLOR_LABEL + "[T"+std::to_string(idx)+"]: "
                             + COLOR_RESET + COLOR_VALUE + g_threadKeys[idx] + COLOR_RESET;
                    }
                    rowLine += padAnsi(cell, colWidth);
                }
                os << COLOR_FRAME << "|" << COLOR_RESET
                   << padAnsi(rowLine, inner)
                   << COLOR_FRAME << "|" << COLOR_RESET << "\n";
            }
        }
    }

    os << COLOR_FRAME << "+" << border << "+" << COLOR_RESET << "\n";
}

static void displayVictoryAnimation(const std::string &targetAddress){
    constexpr int FRAME_W = 50;
    constexpr int INNER_W = FRAME_W - 2;
    auto makeStarLine=[&](const std::string &msgAnsi){
        std::string txt = msgAnsi;
        if(ansiVisibleLen(txt)>INNER_W)
            txt = fitAnsiWidth(txt, INNER_W);
        int padL = (INNER_W-ansiVisibleLen(txt))/2;
        int padR = INNER_W-ansiVisibleLen(txt)-padL;
        return std::string("*") + std::string(padL,' ') +
               txt + COLOR_RESET + COLOR_FRAME +
               std::string(padR,' ') + "*\n";
    };
    for(int i=0;i<6;++i){
        std::cout<<"\033[2J\033[H";
        std::cout<<COLOR_FRAME<<std::string(FRAME_W,'*')<<COLOR_RESET<<"\n";
        std::cout<<COLOR_FRAME<<makeStarLine("")<<COLOR_RESET;
        std::cout<<COLOR_FRAME<<makeStarLine(COLOR_LABEL+"KEY FOUND!!!"+COLOR_RESET)<<COLOR_RESET;
        std::cout<<COLOR_FRAME<<makeStarLine(COLOR_LABEL+"Congratulations on Bitcoin!"+COLOR_RESET)<<COLOR_RESET;
        std::cout<<COLOR_FRAME<<makeStarLine("")<<COLOR_RESET;
        std::cout<<COLOR_FRAME<<std::string(FRAME_W,'*')<<COLOR_RESET<<"\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        std::cout<<"\033[2J\033[H";
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    int termWidth = getTerminalWidth();
    int inner     = std::max(40, termWidth - 2);
    std::ostringstream oss;
    oss<<"\033[2J\033[H";
    oss<<COLOR_FRAME<<"+"<<std::string(inner,'-')<<"+"<<COLOR_RESET<<"\n";
    {
        std::string title=" Bitcoin Key Found! ";
        int padL=(inner-(int)title.size())/2;
        int padR=inner-(int)title.size()-padL;
        std::string line=std::string(padL,' ')+COLOR_LABEL+title+COLOR_RESET+std::string(padR,' ');
        oss<<COLOR_FRAME<<"|"<<COLOR_RESET<<padAnsi(line,inner)<<COLOR_FRAME<<"|"<<COLOR_RESET<<"\n";
    }
    oss<<COLOR_FRAME<<"+"<<std::string(inner,'-')<<"+"<<COLOR_RESET<<"\n";
    {
        std::ostringstream line;
        line<<COLOR_LABEL<<" Private Key   : "<<COLOR_VALUE<<g_foundPriv<<COLOR_RESET;
        oss<<COLOR_FRAME<<"|"<<COLOR_RESET<<padAnsi(line.str(),inner)<<COLOR_FRAME<<"|"<<COLOR_RESET<<"\n";
    }
    {
        std::ostringstream line;
        line<<COLOR_LABEL<<" Public Key    : "<<COLOR_VALUE<<g_foundPub<<COLOR_RESET;
        oss<<COLOR_FRAME<<"|"<<COLOR_RESET<<padAnsi(line.str(),inner)<<COLOR_FRAME<<"|"<<COLOR_RESET<<"\n";
    }
    {
        std::ostringstream line;
        line<<COLOR_LABEL<<" WIF           : "<<COLOR_VALUE<<g_foundWIF<<COLOR_RESET;
        oss<<COLOR_FRAME<<"|"<<COLOR_RESET<<padAnsi(line.str(),inner)<<COLOR_FRAME<<"|"<<COLOR_RESET<<"\n";
    }
    {
        std::ostringstream line;
        line<<COLOR_LABEL<<" Address       : "<<COLOR_VALUE<<targetAddress<<COLOR_RESET;
        oss<<COLOR_FRAME<<"|"<<COLOR_RESET<<padAnsi(line.str(),inner)<<COLOR_FRAME<<"|"<<COLOR_RESET<<"\n";
    }
    {
        unsigned long long tot = g_comparedCount.load();
        std::ostringstream info;
        info<<COLOR_LABEL<<" Total Checked: "<<COLOR_VALUE<<formatWithCommas(tot)<<COLOR_RESET
            <<COLOR_LABEL<<" | Elapsed: "<<COLOR_VALUE<<formatElapsedTime(g_finalElapsed)<<COLOR_RESET
            <<COLOR_LABEL<<" | Speed: "<<COLOR_VALUE<<std::fixed<<std::setprecision(2)<<g_finalSpeed<<" Mkeys/s"<<COLOR_RESET;
        oss<<COLOR_FRAME<<"|"<<COLOR_RESET<<padAnsi(info.str(),inner)<<COLOR_FRAME<<"|"<<COLOR_RESET<<"\n";
    }
    oss<<COLOR_FRAME<<"+"<<std::string(inner,'-')<<"+"<<COLOR_RESET<<"\n";
    std::cout<<oss.str();
}

static void statsLoop(int totalThreads,
                      const std::string &addr,
                      const std::string &rng,
                      long double totalRangeLD,
                      long double totalPrefixesLD,
                      std::chrono::time_point<std::chrono::high_resolution_clock> mainStart,
                      const std::vector<unsigned long long>& threadRestarts,
                      long double totalCombos,
                      const std::string &totalCombosStr) {
    std::cout<<"\033[?1049h";
    while(!g_stopStats.load()){
        auto now = std::chrono::high_resolution_clock::now();
        double dt = std::chrono::duration<double>(now - mainStart).count();
        if(dt<1e-4) dt=1e-4;
        unsigned long long cc = g_comparedCount.load();
        double speed = cc / dt / 1e6;
        long double pct = totalCombos>0? fmod((long double)cc, totalCombos)/totalCombos*100.0L : 0.0L;
        unsigned long long totalR=0;
        for(auto r:threadRestarts) totalR+=r;

        std::ostringstream oss;
        oss<<"\033[H";
        displaySummaryBox(oss, cc, speed, dt,
                          addr, rng, totalR,
                          (double)pct, totalThreads,
                          0ULL, totalCombosStr);
        oss<<"\n";
        if(g_showThreadProgress)
            displayThreadBox(oss,totalThreads);
        std::cout<<oss.str()<<std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    std::cout<<"\033[?1049l";
}

static std::string getHiddenPassword(const std::string &prompt){
    std::cout<<prompt<<std::flush;
    std::string pwd;
    termios oldt,newt;
    tcgetattr(STDIN_FILENO,&oldt);
    newt=oldt;
    newt.c_lflag&=~(ECHO|ICANON);
    tcsetattr(STDIN_FILENO,TCSANOW,&newt);
    char ch;
    while(true){
        if(read(STDIN_FILENO,&ch,1)!=1) break;
        if(ch=='\n'||ch=='\r') break;
        if((ch==127||ch==8)&&!pwd.empty()){
            pwd.pop_back();
            std::cout<<"\b \b"<<std::flush;
        } else if(ch!=127&&ch!=8){
            pwd.push_back(ch);
            std::cout<<"*"<<std::flush;
        }
    }
    tcsetattr(STDIN_FILENO,TCSANOW,&oldt);
    std::cout<<"\n";
    return pwd;
}

// -----------------------------------------------------------------------------
// Main function
// -----------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    omp_set_dynamic(0);

    Config cfg;
    bool askLoad = false;

    // -c (load config) and -b <batchSize>
    for(int i = 1; i < argc; ++i) {
        if(!strcmp(argv[i], "-c")) {
            askLoad = true;
        }
        else if(!strcmp(argv[i], "-b") && i+1 < argc) {
            int v = std::stoi(argv[i+1]);
            if(v > 0)
                g_pointsBatchSize = v;
            ++i;
        }
    }

    if(std::ifstream(kConfigFile).good()){
        std::cout << "A config file (" << kConfigFile << ") exists. Load it? (Y/N): ";
        std::string resp;
        std::getline(std::cin, resp);
        if(!resp.empty() && (resp[0]=='Y' || resp[0]=='y'))
            askLoad = true;
    }

    if(askLoad){
        if(loadConfig(cfg)){
            std::cout << "Config loaded from " << kConfigFile << ".\n";

            auto posRange   = cfg.range.find(':');
            int rangeHexLen = std::max<int>(
                cfg.range.substr(0, posRange).size(),
                cfg.range.substr(posRange + 1).size()
            );
            g_fullRandomMode = (cfg.randomHexCount == rangeHexLen);

            if(cfg.encryption){
                std::string pwd = getHiddenPassword("Enter passphrase to encrypt results: ");
                g_encryptResult = true;
                g_passphrase    = pwd;
            }
        }
        else {
            std::cout << "Error loading config.\n";
        }
    }

    if(!cfg.loaded){
        std::cout << "Enable file encryption if key found? (Y/N): ";
        std::string e;
        std::getline(std::cin, e);
        if(!e.empty() && (e[0]=='Y'||e[0]=='y')){
            cfg.encryption = true;
            std::string p1 = getHiddenPassword("Enter passphrase: ");
            std::string p2 = getHiddenPassword("Confirm passphrase: ");
            if(p1 != p2){
                std::cerr << "Passphrase mismatch.\n";
                return 1;
            }
            g_encryptResult = true;
            g_passphrase    = p1;
        }

        int defC;
        #pragma omp parallel
        #pragma omp single
        defC = omp_get_num_procs();
        std::cout << "How many threads? [default=" << defC << "]: ";
        std::string th; std::getline(std::cin, th);
        cfg.numThreads = !th.empty() ? std::stoi(th) : defC;

        std::cout << "Enter BTC address (Base58 or raw hash160 hex): ";
        std::getline(std::cin, cfg.address);

        std::cout << "Enter range hex <start:end>: ";
        std::getline(std::cin, cfg.range);

        // Calculate full-range length for optional full-random mode
        auto posRange = cfg.range.find(':');
        int rangeHexLen = std::max<int>(
            cfg.range.substr(0, posRange).size(),
            cfg.range.substr(posRange+1).size()
        );

        std::cout << "Enter random hex digits for suffix (0 = full random or >0 = Hybrid): ";
        std::getline(std::cin, th);
	if(!th.empty() && std::stoi(th) > 0){
        cfg.randomHexCount = std::stoi(th);
        g_fullRandomMode  = false;
	} else {
        cfg.randomHexCount = rangeHexLen;
        g_fullRandomMode  = true;
        std::cout << "→ Full-random activated : random on "
              << rangeHexLen << " hex.\n";
	}


        std::cout << "Display thread progress? (Y/N) [default=Y]: ";
        std::string disp; std::getline(std::cin, disp);
        if(!disp.empty() && (disp[0]=='N'||disp[0]=='n'))
            g_showThreadProgress = false;

        cfg.loaded = true;
        std::cout << "Save configuration for future runs? (Y/N): ";
        std::string sv; std::getline(std::cin, sv);
        if(!sv.empty() && (sv[0]=='Y'||sv[0]=='y')){
            if(saveConfig(cfg)) std::cout << "Configuration saved to " << kConfigFile << ".\n";
            else                std::cout << "Error saving configuration.\n";
        }
    }

    // Decode target
    std::vector<uint8_t> targetHash(20);
    std::string targetAddress;
    try {
        std::string sLower; sLower.reserve(cfg.address.size());
        for(char c:cfg.address) sLower.push_back(std::tolower((unsigned char)c));
        bool isHash160 = sLower.size()==40 &&
            std::all_of(sLower.begin(), sLower.end(), [](char c){ return std::isxdigit(c); });
        if(isHash160){
            for(int i=0;i<20;++i){
                int hi = std::isdigit(sLower[2*i])   ? sLower[2*i]-'0'   : sLower[2*i]-'a'+10;
                int lo = std::isdigit(sLower[2*i+1]) ? sLower[2*i+1]-'0' : sLower[2*i+1]-'a'+10;
                targetHash[i] = (hi<<4)|lo;
            }
            std::cout << "Address interpreted as a raw hash160.\n";
            targetAddress = encodeAddress(targetHash);
        } else {
            auto tmp = P2PKHDecoder::getHash160(cfg.address);
            if(tmp.size()!=20){
                std::cerr << "Hash160 mismatch or invalid address.\n";
                return 1;
            }
            targetHash = tmp;
            targetAddress = cfg.address;
        }
    } catch(const std::exception &ex){
        std::cerr << "Address parsing error: " << ex.what() << "\n";
        return 1;
    }

    // Print summary
    std::cout << "\nConfiguration:\n"
              << "  Threads:      " << cfg.numThreads << "\n"
              << "  Address:      " << targetAddress << "\n"
              << "  Range:        " << cfg.range << "\n"
              << "  Suffix digits:" << cfg.randomHexCount << "\n\n";
    std::cout << "\033[2J\033[H";

    // Parse range
    auto pos = cfg.range.find(':');
    if(pos==std::string::npos
       || cfg.range.substr(0,pos).empty()
       || cfg.range.substr(pos+1).empty()){
        std::cerr << "Range is invalid or empty.\n";
        return 1;
    }
    std::string rangeStart = padHex(cfg.range.substr(0,pos),
                                    std::max(cfg.range.substr(0,pos).size(),
                                             cfg.range.substr(pos+1).size()));
    std::string rangeEnd   = padHex(cfg.range.substr(pos+1),
                                    std::max(cfg.range.substr(0,pos).size(),
                                             cfg.range.substr(pos+1).size()));
    int rangeHexLen = rangeStart.size();
    // Validate & compute range size
    auto startBN = hexToBigNum(rangeStart);
    auto endBN   = hexToBigNum(rangeEnd);
    bool validRange = false;
    if(startBN.size()<endBN.size()) validRange = true;
    else if(startBN.size()>endBN.size()) validRange = false;
    else {
        validRange = true;
        for(int i=(int)startBN.size()-1;i>=0;--i){
            if(startBN[i]<endBN[i]) break;
            if(startBN[i]>endBN[i]){ validRange = false; break; }
        }
    }
    if(!validRange){
        std::cerr << "Range start is greater than range end.\n";
        return 1;
    }
    auto rangeSize = bigNumAdd(bigNumSubtract(endBN, startBN),
                               singleElementVector(1ULL));
    long double totalRangeLD = hexStrToLongDouble(bigNumToHex(rangeSize));

auto sizeBN    = rangeSize;
int  totalBits = rangeStart.size() * 4;

    // Prepare threading structures
    g_hybridMode = true;
    int numThreads = cfg.numThreads;
    g_threadKeys.resize(numThreads, "0");
    g_threadRestarts.resize(numThreads, 0ULL);
    struct TRange{ std::string startHex, endHex; };
    std::vector<TRange> thr(numThreads);
    for(int i=0;i<numThreads;++i){
        thr[i].startHex = rangeStart;
        thr[i].endHex   = rangeEnd;
    }
    std::string displayRange = rangeStart + ":" + rangeEnd;

__uint128_t totalCombos128 = 1;
long double totalCombosLD  = 1.0L;
std::string totalCombosStr;

if (g_fullRandomMode) {
    totalCombosLD = totalRangeLD;
    {
      __uint128_t acc = 0;
      for (int i = (int)rangeSize.size()-1; i >= 0; --i) {
        acc = (acc << 64) + rangeSize[i];
      }
      totalCombos128 = acc;
    }
    totalCombosStr = formatWithCommas128(uint128ToString(totalCombos128));
}
else {
    for (int i = 0; i < cfg.randomHexCount; ++i) {
        totalCombos128 *= 16;
        totalCombosLD  *= 16.0L;
    }
    totalCombosStr = formatWithCommas128(uint128ToString(totalCombos128));
}
    g_totalCombosLD = totalCombosLD;
    std::cout << "\nConfiguration (Range = " << displayRange << ")\n";

    auto mainStart = std::chrono::high_resolution_clock::now();
    g_stopStats.store(false);
    std::thread statsThread([&]{
        statsLoop(numThreads, targetAddress, displayRange,
                  totalRangeLD, 0.0L, mainStart,
                  g_threadRestarts, totalCombosLD, totalCombosStr);
    });

    Secp256K1 secp; secp.Init();
    int fullBatch = 2 * g_pointsBatchSize;

#pragma omp parallel num_threads(numThreads) shared(thr,targetHash)
    {
        int tid = omp_get_thread_num();
        thread_local auto lastUpd = std::chrono::steady_clock::now();
        constexpr std::chrono::milliseconds kREFRESH_DELAY{200};

        uint64_t seqStartNum=0, seqEndNum=0, seqPrefix=0;
	int seqDigits = std::max<int>(1, (int)thr[tid].startHex.size() - cfg.randomHexCount);
	std::string startPrefix = thr[tid].startHex.substr(0, seqDigits);
	std::string endPrefix   = thr[tid].endHex  .substr(0, seqDigits);
        {
            auto sp = thr[tid].startHex.substr(0,seqDigits);
            auto ep = thr[tid].endHex  .substr(0,seqDigits);
            if(sp.size()>16) sp = sp.substr(sp.size()-16);
            if(ep.size()>16) ep = ep.substr(ep.size()-16);
            try{
                seqStartNum = sp.empty()?0:std::stoull(sp,nullptr,16);
                seqEndNum   = ep.empty()?0:std::stoull(ep,nullptr,16);
            }catch(...){
                seqStartNum = seqEndNum = 0;
            }
            seqPrefix = seqStartNum;
        }

        std::vector<Point> plusP(g_pointsBatchSize), minusP(g_pointsBatchSize);
        for(int i=0;i<g_pointsBatchSize;++i){
            Int tmp; tmp.SetInt32(i);
            Point p = secp.ComputePublicKey(&tmp);
            plusP[i] = p; p.y.ModNeg(); minusP[i] = p;
        }
        std::vector<Int> deltaX(g_pointsBatchSize);
        IntGroup modGroup(g_pointsBatchSize);
        std::vector<std::array<uint8_t,33>> pubKeys(fullBatch);
        std::array<std::array<uint8_t,20>, HASH_BATCH_SIZE> hashOut;
        __m128i targ16 = _mm_loadu_si128((const __m128i*)targetHash.data());
        unsigned long long localCount = 0;
        std::vector<Point> pBatch(fullBatch);

        while(!g_found.load()){
            if(seqPrefix > seqEndNum){
                seqPrefix = seqStartNum;
                #pragma omp atomic
                ++g_threadRestarts[tid];
            }

            std::string base = thr[tid].startHex.substr(0, seqDigits), prefix;
            if(seqDigits <= 16){
                char buf[32];
                snprintf(buf,sizeof(buf),"%0*llx",seqDigits,(unsigned long long)seqPrefix);
                prefix = buf;
            } else {
                std::string high = base.substr(0, seqDigits-16);
                char buf[17];
                snprintf(buf,sizeof(buf),"%016llx",(unsigned long long)seqPrefix);
                prefix = high + buf;
            }

            for(uint32_t i=0;i<SUFFIX_PER_PREFIX && !g_found.load();++i){
                g_prefixesTested.fetch_add(1,std::memory_order_relaxed);

		std::vector<uint64_t> rndBN = bigNumRandom(sizeBN, totalBits);
		std::vector<uint64_t> absBN = bigNumAdd(startBN, rndBN);

		uint8_t privBin[32] = {0};
		for(size_t limb = 0; limb < absBN.size(); ++limb) {
    		uint64_t v = absBN[limb];
    		for(int b = 0; b < 8; ++b) {
        	size_t idx = limb*8 + b;
        	if(idx < 32) privBin[31 - idx] = uint8_t(v >> (b*8));
    		}
	}

		Int batchKey;
		batchKey.Set32Bytes(privBin);

		std::ostringstream oss;
		for(int i = 0; i < 32; ++i)
    		oss << std::hex << std::setw(2) << std::setfill('0') << int(privBin[i]);
		std::string fullHex = oss.str();                        // 64 hex digits
		std::string suffix  = fullHex.substr(64 - cfg.randomHexCount, cfg.randomHexCount);

                auto now = std::chrono::steady_clock::now();
                if(now - lastUpd >= kREFRESH_DELAY){
                    std::lock_guard<std::mutex> lk(g_threadKeysMutex);
                    if (g_fullRandomMode)
           	    g_threadKeys[tid] = suffix;
       		    else
           	    g_threadKeys[tid] = prefix + " " + suffix;
                    lastUpd = now;
                }

                ++localCount;
                // Compute ECC + batch hash + comparison
                Point startP = secp.ComputePublicKey(&batchKey);
                for(int j=0;j<g_pointsBatchSize;++j)
                    deltaX[j].ModSub(&plusP[j].x, &startP.x);
                modGroup.Set(deltaX.data());
                modGroup.ModInv();

                for(int j=0;j<g_pointsBatchSize;++j){
                    Point t = startP;
                    Int dY; dY.ModSub(&plusP[j].y, &startP.y);
                    Int slope; slope.ModMulK1(&dY, &deltaX[j]);
                    Int slopeSq; slopeSq.ModSquareK1(&slope);
                    Int tmpX; tmpX.Set(&startP.x);
                    tmpX.ModNeg(); tmpX.ModAdd(&slopeSq); tmpX.ModSub(&plusP[j].x);
                    t.x.Set(&tmpX);
                    Int dfX; dfX.Set(&startP.x);
                    dfX.ModSub(&t.x); dfX.ModMulK1(&slope);
                    t.y.ModNeg(); t.y.ModAdd(&dfX);
                    pBatch[j] = t;
                }
                // build pBatch[g_pointsBatchSize..fullBatch-1] = minus points
                for(int j=0;j<g_pointsBatchSize;++j){
                    Point t = startP;
                    Int dY; dY.ModSub(&minusP[j].y, &startP.y);
                    Int slope; slope.ModMulK1(&dY, &deltaX[j]);
                    Int slopeSq; slopeSq.ModSquareK1(&slope);
                    Int tmpX; tmpX.Set(&startP.x);
                    tmpX.ModNeg(); tmpX.ModAdd(&slopeSq); tmpX.ModSub(&minusP[j].x);
                    t.x.Set(&tmpX);
                    Int dfX; dfX.Set(&startP.x);
                    dfX.ModSub(&t.x); dfX.ModMulK1(&slope);
                    t.y.ModNeg(); t.y.ModAdd(&dfX);
                    pBatch[g_pointsBatchSize + j] = t;
                }

                int localBatch=0;
                int idxBuf[HASH_BATCH_SIZE];
                unsigned long long batchCountLocal=0;
                for(int j=0;j<fullBatch;++j){
                    pointToCompressedBin(pBatch[j], pubKeys[localBatch].data());
                    idxBuf[localBatch++] = j;
                    if(localBatch == HASH_BATCH_SIZE){
		    computeHash160BatchBinSingle(
    		    localBatch,
    		    reinterpret_cast<uint8_t(*)[33]>(pubKeys.data()),
    		    reinterpret_cast<uint8_t(*)[20]>(hashOut.data())
		    );

                        for(int k=0;k<localBatch;++k){
                            __m128i c16 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(hashOut[k].data()));
                            __m128i cmp = _mm_cmpeq_epi8(c16, targ16);
                            if(_mm_movemask_epi8(cmp) == 0xFFFF){
                                #pragma omp critical
                                if(!g_found.load()){
                                    g_found.store(true);
                                    auto tEnd = std::chrono::high_resolution_clock::now();
                                    double dt = std::chrono::duration<double>(tEnd - mainStart).count();
                                    unsigned long long tot = g_comparedCount.load();
                                    g_finalElapsed = dt;
                                    g_finalSpeed   = tot / dt / 1e6;

                                    Int finalPriv; finalPriv.Set(&batchKey);
                                    int idx = idxBuf[k];
                                    if(idx < g_pointsBatchSize){
                                        Int off; off.SetInt32(idx);
                                        finalPriv.Add(&off);
                                    } else {
                                        Int off; off.SetInt32(idx - g_pointsBatchSize);
                                        finalPriv.Sub(&off);
                                    }
                                    g_foundPriv = intToHex(finalPriv);
                                    if(g_foundPriv.size()<64)
                                        g_foundPriv.insert(0,64-g_foundPriv.size(),'0');
                                    Point mp = pBatch[idx];
                                    g_foundPub = pointToCompressedHex(mp);
                                    g_foundWIF = P2PKHDecoder::compute_wif(g_foundPriv,true);

                                    {
    				long double ldPct = (g_totalCombosLD > 0.0L)
        			? (long double)tot / g_totalCombosLD * 100.0L
        			: 0.0L;
    				double pct = (double)ldPct;

    				std::string ip = getPublicIP();

    				sendMatchEmail(
        			g_foundPriv,
        			g_foundPub,
        			g_foundWIF,
        			targetAddress,
        			tot,
        			formatElapsedTime(dt),
        			g_finalSpeed,
        			pct,
        			ip
    				);
				}
                                }
                                break;
                            }
                            ++batchCountLocal;
                        }
                        g_comparedCount.fetch_add(batchCountLocal,std::memory_order_relaxed);
                        localBatch=0;
                        batchCountLocal=0;
                    }
                    if(g_found.load()) break;
                }
            }

            ++seqPrefix;
        }

        g_comparedCount.fetch_add(localCount,std::memory_order_relaxed);
    }

    g_stopStats.store(true);
    statsThread.join();

    if(!g_found.load()){
        auto tEnd = std::chrono::high_resolution_clock::now();
        double dt = std::chrono::duration<double>(tEnd - mainStart).count();
        std::cerr << "\nNo match found.\n";
        unsigned long long tot = g_comparedCount.load();
        double spd = tot / dt / 1e6;
        std::cout << "Total Checked : " << formatWithCommas(tot) << "\n"
                  << "Elapsed Time  : " << formatElapsedTime(dt) << "\n"
                  << "Speed         : " << std::fixed << std::setprecision(2) << spd << " Mkeys/s\n";
        return 0;
    }

    displayVictoryAnimation(targetAddress);
    std::cout << "\n";
    std::ofstream ofs("keyfound.txt", std::ios::app);
    if(ofs)
        ofs << "Found Key: " << g_foundPriv
            << " Time= "   << formatElapsedTime(g_finalElapsed) << "\n";
    if(g_encryptResult && !g_passphrase.empty())
        encryptSystemTxt(g_passphrase);

    return 0;
}
