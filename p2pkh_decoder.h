#ifndef P2PKH_DECODER_H
#define P2PKH_DECODER_H

#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>

namespace P2PKHDecoder {

std::vector<uint8_t> getHash160(const std::string& p2pkh_address);
std::string compute_wif(const std::string& private_key_hex, bool compressed);

} // namespace P2PKHDecoder

#endif // P2PKH_DECODER_H
