/**
 * @file Sec/HKDF.cpp
 * @brief HKDF-BLAKE2b implementation (RFC 5869 extract-then-expand).
 */

#include "../../include/Sec/HKDF.hpp"

namespace Sec {

String hkdf(const String &secret, const String &salt, const String &info, int length) {
  const int hashLen = 64; // BLAKE2b-512 output
  if (length <= 0 || length > 255 * hashLen)
    return String();

  // 1. Extract: PRK = BLAKE2b(secret, key = salt)
  String prk = hash(secret, hashLen, salt);

  // 2. Expand: T(i) = BLAKE2b(T(i-1) || info || counter, key = PRK)
  int numBlocks = (length + hashLen - 1) / hashLen;
  String okm;
  String t;

  for (int i = 1; i <= numBlocks; i++) {
    String expandInput;
    expandInput += t;
    expandInput += info;
    expandInput.push((u8)i);
    t = hash(expandInput, hashLen, prk);
    okm += t;
  }

  return okm.begin(0, length);
}

String hkdf(const String &secret, const String &info, int length) {
  return hkdf(secret, String(), info, length);
}

} // namespace Sec

