#include "p2pkh_decoder.h"
#include "sha256_avx2.h"
#include "ripemd160_avx2.h"
#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace P2PKHDecoder {

const std::string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::vector<uint8_t> base58_decode(const std::string& input) {
    std::vector<uint8_t> bytes;
    bytes.push_back(0);

    for (char c : input) {
        size_t index = BASE58_ALPHABET.find(c);
        if (index == std::string::npos) {
            throw std::invalid_argument("Недопустимый символ в строке Base58");
        }

        int carry = static_cast<int>(index);
        for (size_t i = 0; i < bytes.size(); ++i) {
            carry += 58 * bytes[i];
            bytes[i] = carry & 0xFF;
            carry >>= 8;
        }

        while (carry > 0) {
            bytes.push_back(carry & 0xFF);
            carry >>= 8;
        }
    }

    size_t leading_zero_count = 0;
    for (char c : input) {
        if (c == '1') {
            ++leading_zero_count;
        } else {
            break;
        }
    }

    std::reverse(bytes.begin(), bytes.end());

    while (!bytes.empty() && bytes[0] == 0) {
        bytes.erase(bytes.begin());
    }

    std::vector<uint8_t> result;
    for (size_t i = 0; i < leading_zero_count; ++i) {
        result.push_back(0x00);
    }
    result.insert(result.end(), bytes.begin(), bytes.end());

    return result;
}

std::string base58_encode(const std::vector<uint8_t>& input) {
    std::vector<int> digits;
    digits.push_back(0);

    for (uint8_t byte : input) {
        int carry = byte;
        for (size_t i = 0; i < digits.size(); ++i) {
            carry += digits[i] * 256;
            digits[i] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }

    size_t leading_zero_count = 0;
    for (uint8_t byte : input) {
        if (byte == 0x00) {
            ++leading_zero_count;
        } else {
            break;
        }
    }

    std::string encoded;
    for (size_t i = 0; i < leading_zero_count; ++i) {
        encoded += '1';
    }

    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        encoded += BASE58_ALPHABET[*it];
    }

    return encoded;
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    const char hex_chars[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        hex += hex_chars[(byte >> 4) & 0xF];
        hex += hex_chars[byte & 0xF];
    }
    return hex;
}

std::vector<uint8_t> compute_sha256(const std::vector<uint8_t>& data) {
    if (data.size() > 56) {
        throw std::invalid_argument("Данные слишком длинные для одного блока SHA256.");
    }

    std::vector<uint8_t> padded(64, 0x00);
    memcpy(padded.data(), data.data(), data.size());
    padded[data.size()] = 0x80;

    uint64_t bit_length = static_cast<uint64_t>(data.size()) * 8;
    uint8_t length_bytes[8];
    for (int i = 0; i < 8; ++i) {
        length_bytes[i] = (bit_length >> (56 - 8 * i)) & 0xFF;
    }
    memcpy(padded.data() + 56, length_bytes, 8);

    unsigned char hash0[32], hash1_output[32], hash2_output[32], hash3_output[32],
               hash4_output[32], hash5_output[32], hash6_output[32], hash7_output[32];

    sha256avx2_8B(
        padded.data(),
        padded.data(),
        padded.data(),
        padded.data(),
        padded.data(),
        padded.data(),
        padded.data(),
        padded.data(),
        hash0,
        hash1_output,
        hash2_output,
        hash3_output,
        hash4_output,
        hash5_output,
        hash6_output,
        hash7_output
    );

    return std::vector<uint8_t>(hash0, hash0 + 32);
}

std::vector<uint8_t> compute_hash160(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> sha256_hash = compute_sha256(data);

    std::vector<uint8_t> ripemd_padded(64, 0x00);
    memcpy(ripemd_padded.data(), sha256_hash.data(), sha256_hash.size());
    ripemd_padded[sha256_hash.size()] = 0x80;

    uint8_t bit_length_ripemd[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
    memcpy(ripemd_padded.data() + 56, bit_length_ripemd, 8);

    unsigned char ripemd_output[20];
    ripemd160avx2::ripemd160avx2_32(
        ripemd_padded.data(),
        ripemd_padded.data(),
        ripemd_padded.data(),
        ripemd_padded.data(),
        ripemd_padded.data(),
        ripemd_padded.data(),
        ripemd_padded.data(),
        ripemd_padded.data(),
        ripemd_output,
        ripemd_output,
        ripemd_output,
        ripemd_output,
        ripemd_output,
        ripemd_output,
        ripemd_output,
        ripemd_output
    );

    return std::vector<uint8_t>(ripemd_output, ripemd_output + 20);
}

std::vector<uint8_t> getHash160(const std::string& p2pkh_address) {
    std::vector<uint8_t> decoded = base58_decode(p2pkh_address);

    if (decoded.size() != 25) {
        throw std::invalid_argument("Некорректная длина декодированных данных.");
    }

    std::vector<uint8_t> data(decoded.begin(), decoded.begin() + 21);
    std::vector<uint8_t> checksum(decoded.begin() + 21, decoded.end());

    std::vector<uint8_t> hash1 = compute_sha256(data);
    std::vector<uint8_t> hash2 = compute_sha256(hash1);

    if (!std::equal(hash2.begin(), hash2.begin() + 4, checksum.begin())) {
        throw std::invalid_argument("Неверная контрольная сумма.");
    }

    std::vector<uint8_t> hash160_vec(data.begin() + 1, data.end());

    return hash160_vec;
}

std::string compute_wif(const std::string& private_key_hex, bool compressed) {
    if (private_key_hex.length() != 64) {
        throw std::invalid_argument("Приватный ключ должен быть 64 символа HEX.");
    }

    std::vector<uint8_t> private_key_bytes;
    private_key_bytes.reserve(32);
    for (size_t i = 0; i < private_key_hex.length(); i += 2) {
        uint8_t byte = std::stoi(private_key_hex.substr(i, 2), nullptr, 16);
        private_key_bytes.push_back(byte);
    }

    std::vector<uint8_t> wif_bytes;
    wif_bytes.push_back(0x80);
    wif_bytes.insert(wif_bytes.end(), private_key_bytes.begin(), private_key_bytes.end());
    if (compressed) {
        wif_bytes.push_back(0x01);
    }

    std::vector<uint8_t> hash1 = compute_sha256(wif_bytes);
    std::vector<uint8_t> hash2 = compute_sha256(hash1);

    std::vector<uint8_t> checksum(hash2.begin(), hash2.begin() + 4);
    wif_bytes.insert(wif_bytes.end(), checksum.begin(), checksum.end());

    return base58_encode(wif_bytes);
}

} // namespace P2PKHDecoder

