#ifndef P2PKH_DECODER_H
#define P2PKH_DECODER_H

#include <vector>
#include <string>
#include <cstdint>

namespace P2PKHDecoder {

/**
 * Decode a Base58 P2PKH address (with 1-byte version + 20-byte hash160 + 4-byte checksum)
 * and return the 20-byte payload (hash160).
 *
 * @param p2pkh_address  Base58Check-encoded P2PKH address.
 * @throws std::invalid_argument on decoding or checksum failure.
 */
std::vector<uint8_t> getHash160(const std::string& p2pkh_address);

/**
 * Compute a WIF (Wallet Import Format) string from a 32-byte private key hex.
 *
 * @param private_key_hex  64-character hex string.
 * @param compressed       append 0x01 and set compressed-pubkey flag if true.
 * @return Base58Check-encoded WIF string.
 * @throws std::invalid_argument on bad input length.
 */
std::string compute_wif(const std::string& private_key_hex, bool compressed);

} // namespace P2PKHDecoder

#endif // P2PKH_DECODER_H
