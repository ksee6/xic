/**
 * @file A2id.cpp
 * @brief Implementation of Argon2id key derivation and hashing helper.
 */

#include "../../include/Sec/A2id.hpp"

namespace Sec {

String A2id::hkdf(const String &password, const String &salt, usz outlen,
                  u32 m_cost, u32 t_cost, u32 parallelism) {
    PwhashParams p;
    p.outlen = outlen;
    p.m_cost = m_cost;
    p.t_cost = t_cost;
    p.parallelism = parallelism;
    return pwhash(password, salt, p);
}

} // namespace Sec

