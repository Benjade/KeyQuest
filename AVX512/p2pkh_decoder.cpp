// p2pkh_decoder.cpp
#include "p2pkh_decoder.h"

#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

#include "sha256_avx512.h"
#include "ripemd160_avx512.h"

namespace P2PKHDecoder {

static const std::string BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::vector<uint8_t> base58_decode(const std::string& input) {
    std::vector<uint8_t> bytes{0};
    for (char c : input) {
        auto idx = BASE58_ALPHABET.find(c);
        if (idx == std::string::npos)
            throw std::invalid_argument("Invalid Base58 character");
        int carry = int(idx);
        for (size_t i = 0; i < bytes.size(); ++i) {
            carry += 58 * bytes[i];
            bytes[i] = carry & 0xFF;
            carry >>= 8;
        }
        while (carry) {
            bytes.push_back(carry & 0xFF);
            carry >>= 8;
        }
    }
    // restore leading zeros
    size_t n1 = 0;
    for (char c : input) {
        if (c == '1') ++n1;
        else break;
    }
    std::reverse(bytes.begin(), bytes.end());
    while (!bytes.empty() && bytes[0] == 0) bytes.erase(bytes.begin());
    std::vector<uint8_t> result(n1, 0);
    result.insert(result.end(), bytes.begin(), bytes.end());
    return result;
}

std::string base58_encode(const std::vector<uint8_t>& input) {
    std::vector<int> digits{0};
    for (uint8_t b : input) {
        int carry = b;
        for (size_t i = 0; i < digits.size(); ++i) {
            carry += digits[i] * 256;
            digits[i] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }
    size_t n0 = 0;
    for (uint8_t b : input) {
        if (b == 0) ++n0;
        else break;
    }
    std::string encoded(n0, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        encoded += BASE58_ALPHABET[*it];
    }
    return encoded;
}

std::vector<uint8_t> compute_sha256(const std::vector<uint8_t>& data) {
    if (data.size() > 56)
        throw std::invalid_argument("SHA256 single-block overflow");

    // --- pad into one 64-byte block ---
    uint8_t block[64]{0};
    memcpy(block, data.data(), data.size());
    block[data.size()] = 0x80;
    uint64_t bits = uint64_t(data.size()) * 8;
    for (int i = 0; i < 8; ++i) {
        block[63 - i] = uint8_t((bits >> (8 * i)) & 0xFF);
    }

    // AVX-512: 16-way parallel SHA-256
    alignas(64) uint8_t out[16][32];
    sha256_avx512_16B(
        block, block, block, block,
        block, block, block, block,
        block, block, block, block,
        block, block, block, block,
        out[0], out[1], out[2], out[3],
        out[4], out[5], out[6], out[7],
        out[8], out[9], out[10], out[11],
        out[12], out[13], out[14], out[15]
    );
    // return first hash
    return std::vector<uint8_t>(out[0], out[0] + 32);
}

std::vector<uint8_t> compute_hash160(const std::vector<uint8_t>& data) {
    auto sha = compute_sha256(data);

    // --- pad into one 64-byte RIPEMD block ---
    uint8_t block[64]{0};
    memcpy(block, sha.data(), sha.size());
    block[sha.size()] = 0x80;
    uint64_t rbits = 256;  // longueur en bits
    for (int i = 0; i < 8; ++i) {
        block[63 - i] = uint8_t((rbits >> (8 * i)) & 0xFF);
    }

    // AVX-512: 16-way parallel RIPEMD-160
    alignas(64) uint8_t out[16][20];
    ripemd160avx512::ripemd160avx512_32(
        block, block, block, block,
        block, block, block, block,
        block, block, block, block,
        block, block, block, block,
        out[0], out[1], out[2],  out[3],
        out[4], out[5], out[6],  out[7],
        out[8], out[9], out[10], out[11],
        out[12],out[13],out[14], out[15]
    );
    return std::vector<uint8_t>(out[0], out[0] + 20);
}

std::vector<uint8_t> getHash160(const std::string& addr) {
    auto dec = base58_decode(addr);
    if (dec.size() != 25)
        throw std::invalid_argument("Invalid P2PKH length");
    std::vector<uint8_t> payload(dec.begin(), dec.begin() + 21),
                         checksum(dec.begin() + 21, dec.end());
    auto h1 = compute_sha256(payload);
    auto h2 = compute_sha256(h1);
    if (!std::equal(h2.begin(), h2.begin() + 4, checksum.begin()))
        throw std::invalid_argument("Bad P2PKH checksum");
    // drop version byte:
    return std::vector<uint8_t>(payload.begin() + 1, payload.end());
}

std::string compute_wif(const std::string& priv_hex, bool comp) {
    if (priv_hex.size() != 64)
        throw std::invalid_argument("WIF: private key must be 64 hex chars");
    std::vector<uint8_t> priv;
    priv.reserve(32);
    for (size_t i = 0; i < 64; i += 2) {
        priv.push_back(uint8_t(std::stoi(priv_hex.substr(i,2), nullptr, 16)));
    }

    std::vector<uint8_t> wif{0x80};
    wif.insert(wif.end(), priv.begin(), priv.end());
    if (comp) wif.push_back(0x01);

    auto h1 = compute_sha256(wif);
    auto h2 = compute_sha256(h1);
    wif.insert(wif.end(), h2.begin(), h2.begin() + 4);
    return base58_encode(wif);
}

} // namespace P2PKHDecoder