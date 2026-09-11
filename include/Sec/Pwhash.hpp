/**
 * @file Sec/Pwhash.hpp
 * @brief Password hashing using Argon2id.
 *
 * Argon2id is the OWASP/IETF-recommended password hashing algorithm (RFC 9106).
 * It combines Argon2i (data-independent, side-channel resistant) and
 * Argon2d (data-dependent, GPU-resistant) in a hybrid scheme.
 *
 * API:
 *   // Hash a password with automatic random salt
 *   String hash = Sec::pwhash(password);
 *
 *   // Hash with explicit salt (must be 16 bytes)
 *   String hash = Sec::pwhash(password, salt);
 *
 *   // Custom memory / iterations / parallelism
 *   String hash = Sec::pwhash(password, salt, outlen, m_cost, t_cost, parallelism);
 *
 *   // Verify a password against a stored hash
 *   bool ok = Sec::pwhashVerify(password, storedHash);
 */

#ifndef XI_SEC_PWHASH_HPP
#define XI_SEC_PWHASH_HPP

#include "../Xi/String.hpp"

namespace Sec {

using namespace Xi;

/** @brief Argon2id tuning parameters. */
struct XI_EXPORT PwhashParams {
  usz  outlen      = 32;     ///< Output hash length in bytes.
  u32  m_cost      = 65536;  ///< Memory cost in kibibytes  (64 MiB default).
  u32  t_cost      = 3;      ///< Time cost (iterations).
  u32  parallelism = 1;      ///< Degree of parallelism (lanes).
};

/**
 * @brief Hash a password using Argon2id with a randomly-generated salt.
 *
 * The returned string is self-contained: it encodes the parameters and
 * the salt alongside the raw digest, in a PHC-style format:
 *   $argon2id$v=19$m=M,t=T,p=P$<base64-salt>$<base64-hash>
 *
 * @param password  The plaintext password to hash.
 * @param params    Optional tuning parameters.
 * @return          Encoded password hash string.
 */
XI_EXPORT String pwhash(const String &password, const PwhashParams &params = {});

/**
 * @brief Hash a password using Argon2id with an explicit salt.
 *
 * @param password  The plaintext password to hash.
 * @param salt      Salt bytes (recommended: 16 bytes minimum).
 * @param params    Optional tuning parameters.
 * @return          Raw hash of exactly params.outlen bytes (no encoding).
 */
XI_EXPORT String pwhash(const String &password, const String &salt, const PwhashParams &params = {});

/**
 * @brief Verify a password against an encoded Argon2id hash string.
 *
 * @param password  The plaintext password to verify.
 * @param encoded   The encoded hash produced by pwhash(password).
 * @return          true if the password matches, false otherwise.
 */
XI_EXPORT bool pwhashVerify(const String &password, const String &encoded);

} // namespace Sec

#endif // XI_SEC_PWHASH_HPP

