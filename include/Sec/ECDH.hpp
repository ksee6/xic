/**
 * @file ECDH.hpp
 * @brief Forwarding header to X25519.hpp for backward compatibility.
 */

#ifndef XI_SEC_ECDH_HPP
#define XI_SEC_ECDH_HPP

#include "X25519.hpp"
#include "Key.hpp"

namespace Sec {
inline String sharedKey(const String &priv, const String &pub) { return X::sharedKey(priv, pub); }
inline String publicKey(const String &priv) { return X::publicKey(priv); }
inline KeyPair generateKeyPair() {
    auto kp = X::Keypair::generate();
    return { kp.publicKey.get(), kp.secretKey };
}
inline KeyPair generateKeypair() { return generateKeyPair(); }
}

#endif // XI_SEC_ECDH_HPP
