/**
 * @file JWT.hpp
 * @brief JSON Web Token (JWT) HS256 sealing and verification for the Xi framework.
 */

#ifndef XI_SEC_JWT_HPP
#define XI_SEC_JWT_HPP

#include "../Xi/Tree.hpp"
#include "../Xi/String.hpp"

namespace Sec {

using namespace Xi;

class XI_EXPORT JWT {
public:
    /**
     * @brief Creates a signed HS256 JWT token from a Tree node.
     * @param tree Root node containing claims to encode in payload.
     * @param key Secret key used for HMAC-SHA256 signature.
     * @return Compact serialized JWT token (header.payload.signature).
     */
    static String seal(const Node<void> &tree, const String &key = "");
    static String seal(const Node<void> *tree, const String &key = "");

    /**
     * @brief Creates a signed HS256 JWT token from raw JSON payload string.
     * @param jsonPayload Valid JSON string.
     * @param key Secret key used for HMAC-SHA256 signature.
     * @return Compact serialized JWT token (header.payload.signature).
     */
    static String seal(const String &jsonPayload, const String &key = "");

    /**
     * @brief Verifies and decodes a signed HS256 JWT token.
     * @param token Compact serialized JWT token.
     * @param key Secret key used for HMAC-SHA256 signature verification.
     * @return Root Node<void> with parsed payload. If invalid or JSON parse fails,
     *         returns a Node with isNull = true.
     */
    static Node<void> open(const String &token, const String &key = "");

    /**
     * @brief Checks if a token has a valid HS256 signature and well-formed payload.
     */
    static bool verify(const String &token, const String &key = "");
};

} // namespace Sec

#endif // XI_SEC_JWT_HPP
