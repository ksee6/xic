/**
 * @file Poly1305.hpp
 * @brief RFC 8439 Poly1305 one-time authenticator for the Xi framework.
 */

#ifndef XI_SEC_POLY1305_HPP
#define XI_SEC_POLY1305_HPP

#include "../Xi/String.hpp"
#include "Chacha20.hpp"

namespace Sec {

using namespace Xi;

XI_EXPORT void poly1305(u8 tag[16], const u8 *msg, usz len, const u8 key[32]);

XI_EXPORT String createPoly1305Key(const String &key, u64 nonce);
XI_EXPORT String createPoly1305Key(const String &key, const String &nonce);

XI_EXPORT String sign(const String &key, const String &message);
XI_EXPORT bool verify(const String &key, const String &message, const String &tag);

} // namespace Sec

#endif // XI_SEC_POLY1305_HPP
