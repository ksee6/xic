/**
 * @file ECC.hpp
 * @brief Forwarding header to X25519.hpp for backward compatibility.
 */

#ifndef XI_SEC_ECC_HPP
#define XI_SEC_ECC_HPP

#include "X25519.hpp"

namespace Sec {
using X::clamp;
using X::generateKey;
}

#endif // XI_SEC_ECC_HPP
