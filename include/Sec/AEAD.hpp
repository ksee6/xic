/**
 * @file AEAD.hpp
 * @brief RFC 8439 ChaCha20-Poly1305 Authenticated Encryption with Associated Data.
 */

#ifndef XI_SEC_AEAD_HPP
#define XI_SEC_AEAD_HPP

#include "Chacha20.hpp"
#include "Poly1305.hpp"

namespace Sec {

using namespace Xi;

/**
 * @struct AEADOptions
 * @brief Options and payload for AEAD encryption/decryption.
 */
struct XI_EXPORT AEADOptions {
  String text;        ///< Plaintext or ciphertext.
  String ad;          ///< Associated authenticated data (AAD).
  String tag;         ///< Authentication tag.
  int tagLength = 16; ///< Tag length in bytes (default: 16).
};

XI_EXPORT bool seal(const String &key, u64 nonce, AEADOptions &options);
XI_EXPORT bool seal(const String &key, const String &nonce, AEADOptions &options);

XI_EXPORT bool open(const String &key, u64 nonce, AEADOptions &options);
XI_EXPORT bool open(const String &key, const String &nonce, AEADOptions &options);

inline bool aeadSeal(const String &key, u64 nonce, AEADOptions &options) {
  return seal(key, nonce, options);
}

inline bool aeadOpen(const String &key, u64 nonce, AEADOptions &options) {
  return open(key, nonce, options);
}

} // namespace Sec

#endif // XI_SEC_AEAD_HPP
