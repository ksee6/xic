/**
 * @file Hash.hpp
 * @brief BLAKE2b hashing implementation for the Xi framework.
 */

#ifndef XI_SEC_HASH_HPP
#define XI_SEC_HASH_HPP

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

/**
 * @brief Performs BLAKE2b hashing (unkeyed or keyed).
 * @param input The input data to hash.
 * @param length Length of output hash in bytes (1 to 64, default: 64).
 * @param key Optional key for keyed MAC mode.
 * @return Binary string containing the digest.
 */
XI_EXPORT String hash(const String &input, int length = 64, const String &key = String());

} // namespace Sec

#endif // XI_SEC_HASH_HPP
