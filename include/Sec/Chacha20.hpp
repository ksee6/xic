/**
 * @file Chacha20.hpp
 * @brief RFC 8439 ChaCha20 stream cipher for the Xi framework.
 */

#ifndef XI_SEC_CHACHA20_HPP
#define XI_SEC_CHACHA20_HPP

#include "../Xi/String.hpp"

namespace Sec {

using namespace Xi;

XI_EXPORT void chacha20(u8 *out, const u8 *in, usz len, const u8 key[32], const u8 nonce[12], u32 counter = 0);

XI_EXPORT String createIetfNonce(u64 nonce);

XI_EXPORT String streamXor(const String &key, u64 nonce, const String &text, int counter = 0);
XI_EXPORT String streamXor(const String &key, const String &nonce, const String &text, int counter = 0);

XI_EXPORT String encrypt(const String &key, u64 nonce, const String &plaintext, int counter = 0);
XI_EXPORT String encrypt(const String &key, const String &nonce, const String &plaintext, int counter = 0);

XI_EXPORT String decrypt(const String &key, u64 nonce, const String &ciphertext, int counter = 0);
XI_EXPORT String decrypt(const String &key, const String &nonce, const String &ciphertext, int counter = 0);

} // namespace Sec

#endif // XI_SEC_CHACHA20_HPP
