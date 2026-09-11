/**
 * @file AEAD.cpp
 * @brief RFC 8439 ChaCha20-Poly1305 AEAD implementation.
 */

#include "../../include/Sec/AEAD.hpp"

namespace Sec {

static String makeZeros(usz len) {
  String s;
  if (len == 0) return s;
  u8 *buf = new u8[len];
  for (usz i = 0; i < len; ++i) buf[i] = 0;
  s.pushEach(buf, len);
  delete[] buf;
  return s;
}

bool seal(const String &key, const String &nonce, AEADOptions &options) {
  if (key.size() != 32 || nonce.size() < 12)
    return false;

  // 1. Encrypt with counter = 1
  String ciphertext = streamXor(key, nonce, options.text, 1);

  // 2. Generate one-time Poly1305 key with counter = 0
  String oneTimeKey = createPoly1305Key(key, nonce);

  // 3. Construct authentication block
  u64 adLen = options.ad.size();
  u64 cipherLen = ciphertext.size();
  usz adPad = (16 - (adLen % 16)) % 16;
  usz cipherPad = (16 - (cipherLen % 16)) % 16;

  String dataToAuth;
  dataToAuth += options.ad;
  dataToAuth += makeZeros(adPad);
  dataToAuth += ciphertext;
  dataToAuth += makeZeros(cipherPad);

  for (int i = 0; i < 8; ++i)
    dataToAuth.push((u8)((adLen >> (i * 8)) & 0xFF));
  for (int i = 0; i < 8; ++i)
    dataToAuth.push((u8)((cipherLen >> (i * 8)) & 0xFF));

  // 4. Calculate tag
  String tag = sign(oneTimeKey, dataToAuth);

  options.text = ciphertext;
  options.tag = tag.begin(0, options.tagLength);
  return true;
}

bool seal(const String &key, u64 nonce, AEADOptions &options) {
  String n = createIetfNonce(nonce);
  return seal(key, n, options);
}

bool open(const String &key, const String &nonce, AEADOptions &options) {
  if (key.size() != 32 || nonce.size() < 12)
    return false;

  // 1. Generate one-time Poly1305 key
  String oneTimeKey = createPoly1305Key(key, nonce);

  // 2. Construct authentication block
  u64 adLen = options.ad.size();
  u64 cipherLen = options.text.size();
  usz adPad = (16 - (adLen % 16)) % 16;
  usz cipherPad = (16 - (cipherLen % 16)) % 16;

  String dataToAuth;
  dataToAuth += options.ad;
  dataToAuth += makeZeros(adPad);
  dataToAuth += options.text;
  dataToAuth += makeZeros(cipherPad);

  for (int i = 0; i < 8; ++i)
    dataToAuth.push((u8)((adLen >> (i * 8)) & 0xFF));
  for (int i = 0; i < 8; ++i)
    dataToAuth.push((u8)((cipherLen >> (i * 8)) & 0xFF));

  // 3. Verify tag in constant time
  String calculatedTag = sign(oneTimeKey, dataToAuth);
  if (!options.tag.constantTimeEquals(calculatedTag, options.tagLength))
    return false;

  // 4. Decrypt with counter = 1
  options.text = streamXor(key, nonce, options.text, 1);
  return true;
}

bool open(const String &key, u64 nonce, AEADOptions &options) {
  String n = createIetfNonce(nonce);
  return open(key, n, options);
}

} // namespace Sec
