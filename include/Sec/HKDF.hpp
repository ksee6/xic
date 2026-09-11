/**
 * @file Sec/HKDF.hpp
 * @brief HKDF (HMAC-based Key Derivation Function) using BLAKE2b.
 *
 * Follows RFC 5869 structure — extract then expand — backed by BLAKE2b
 * for both the PRK extraction and the OKM expansion steps.
 *
 * API:  Sec::hkdf(secret, salt, info, length)  — with optional salt
 *       Sec::hkdf(secret, info, length)          — salt = ""
 */

#ifndef XI_SEC_HKDF_HPP
#define XI_SEC_HKDF_HPP

#include "Hash.hpp"

namespace Sec {

using namespace Xi;

/**
 * @brief Derives a key using HKDF-BLAKE2b.
 *
 * @param secret   Input key material (IKM).
 * @param salt     Optional salt.  Pass an empty String to omit.
 * @param info     Context / application-specific info string.
 * @param length   Desired output length in bytes (1 – 16320).
 * @return         Derived key of exactly @p length bytes, or empty on error.
 */
XI_EXPORT String hkdf(const String &secret, const String &salt, const String &info, int length = 32);

/**
 * @brief Derives a key using HKDF-BLAKE2b with no salt.
 *
 * @param secret   Input key material (IKM).
 * @param info     Context / application-specific info string.
 * @param length   Desired output length in bytes (1 – 16320).
 * @return         Derived key of exactly @p length bytes, or empty on error.
 */
XI_EXPORT String hkdf(const String &secret, const String &info, int length = 32);

} // namespace Sec

#endif // XI_SEC_HKDF_HPP

