/**
 * @file Key.hpp
 * @brief Public and private key abstractions for the Xi framework.
 */

#ifndef XI_SEC_KEY_HPP
#define XI_SEC_KEY_HPP

#include "../Xi/String.hpp"

namespace Sec {

using namespace Xi;

/**
 * @struct KeyPair
 * @brief Represents an asymmetric public/private key pair.
 */
struct XI_EXPORT KeyPair {
  String publicKey; ///< The public part of the key pair.
  String secretKey; ///< The secret/private part of the key pair.
};

using Keypair = KeyPair;

} // namespace Sec

#endif // XI_SEC_KEY_HPP
