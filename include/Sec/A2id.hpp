/**
 * @file A2id.hpp
 * @brief Argon2id password-based key derivation (KDF) and hashing.
 */

#ifndef XI_SEC_A2ID_HPP
#define XI_SEC_A2ID_HPP

#include "Pwhash.hpp"

namespace Sec {

using namespace Xi;

struct XI_EXPORT A2id {
    /**
     * @brief Derives a key using Argon2id.
     * @param password Password / passphrase input.
     * @param salt Salt string.
     * @param outlen Desired key length in bytes (default: 32).
     * @param m_cost Memory cost in kibibytes (default: 65536 = 64 MiB).
     * @param t_cost Time cost / iterations (default: 3).
     * @param parallelism Degree of parallelism / lanes (default: 1).
     * @return Raw derived key of length outlen.
     */
    static String hkdf(const String &password, const String &salt, usz outlen = 32,
                       u32 m_cost = 65536, u32 t_cost = 3, u32 parallelism = 1);

    static String kdf(const String &password, const String &salt, usz outlen = 32,
                      u32 m_cost = 65536, u32 t_cost = 3, u32 parallelism = 1) {
        return hkdf(password, salt, outlen, m_cost, t_cost, parallelism);
    }

    static String hash(const String &password, const PwhashParams &params = {}) {
        return pwhash(password, params);
    }

    static bool verify(const String &password, const String &encoded) {
        return pwhashVerify(password, encoded);
    }
};

} // namespace Sec

#endif // XI_SEC_A2ID_HPP

