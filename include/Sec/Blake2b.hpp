/**
 * @file Blake2b.hpp
 * @brief BLAKE2b hashing and HKDF-BLAKE2b key derivation for the Xi framework.
 */

#ifndef XI_SEC_BLAKE2B_HPP
#define XI_SEC_BLAKE2B_HPP

#include "../Xi/String.hpp"

namespace Sec {

using namespace Xi;

struct XI_EXPORT Blake2bCtx {
  u64 h[8];
  u64 t[2];
  u64 f[2];
  u8 buf[128];
  usz buflen;
  usz outlen;
};

XI_EXPORT void blake2bInit(Blake2bCtx *ctx, usz outlen, const void *key = nullptr, usz keylen = 0);
XI_EXPORT void blake2bUpdate(Blake2bCtx *ctx, const void *in, usz inlen);
XI_EXPORT void blake2bFinal(Blake2bCtx *ctx, void *out);

struct XI_EXPORT B2B {
  static String hash(const String &input, int length = 64, const String &key = String());
  static String hash(const char *input, int length = 64, const String &key = String()) {
    return hash(String(input), length, key);
  }
  static String hash(const void *data, usz len, int length = 64, const String &key = String());

  static String hkdf(const String &secret, const String &salt, const String &info, int length = 32);
  static String hkdf(const String &secret, const String &info, int length = 32);
};

// Compatibility aliases
inline String hash(const String &input, int length = 64, const String &key = String()) {
  return B2B::hash(input, length, key);
}
inline String hash(const char *input, int length = 64, const String &key = String()) {
  return B2B::hash(String(input), length, key);
}
inline String hkdf(const String &secret, const String &salt, const String &info, int length = 32) {
  return B2B::hkdf(secret, salt, info, length);
}
inline String hkdf(const String &secret, const String &info, int length = 32) {
  return B2B::hkdf(secret, info, length);
}

} // namespace Sec

#endif // XI_SEC_BLAKE2B_HPP
