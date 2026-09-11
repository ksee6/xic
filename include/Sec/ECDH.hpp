/**
 * @file ECDH.hpp
 * @brief Curve25519 / X25519 Diffie-Hellman and XEdDSA signatures for the Xi framework.
 */

#ifndef XI_SEC_ECDH_HPP
#define XI_SEC_ECDH_HPP

#include "Key.hpp"
#include "../Xi/Array.hpp"

namespace Sec {

using namespace Xi;

XI_EXPORT String sharedKey(const String &privateKey, const String &publicKey);
XI_EXPORT String sharedKey(const KeyPair &ourKeyPair, const String &theirPublicKey);

XI_EXPORT String publicKey(const String &privateKey);
XI_EXPORT KeyPair generateKeyPair();

XI_EXPORT String makeProofed(const Array<KeyPair> &myKeys, const String &theirPublicKey);
XI_EXPORT Array<String> parseProofed(const String &proofed, const String &mySecretKey);

XI_EXPORT String signX(const String &privateKey, const String &text);
XI_EXPORT bool verifyX(const String &publicKey, const String &text, const String &signature);

} // namespace Sec

#endif // XI_SEC_ECDH_HPP
