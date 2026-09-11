/**
 * @file Chacha20.cpp
 * @brief High-performance standalone implementation of RFC 8439 ChaCha20 cipher.
 */

#include "../../include/Sec/Chacha20.hpp"

namespace Sec {

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d) do { \
  a += b; d ^= a; d = ROTL32(d, 16); \
  c += d; b ^= c; b = ROTL32(b, 12); \
  a += b; d ^= a; d = ROTL32(d, 8);  \
  c += d; b ^= c; b = ROTL32(b, 7);  \
} while (0)

static inline u32 load32_le(const u8 *p) {
  return ((u32)p[0]) | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static inline void store32_le(u8 *p, u32 v) {
  p[0] = (u8)v;
  p[1] = (u8)(v >> 8);
  p[2] = (u8)(v >> 16);
  p[3] = (u8)(v >> 24);
}

void chacha20(u8 *out, const u8 *in, usz len, const u8 key[32], const u8 nonce[12], u32 counter) {
  u32 ctx[16];
  ctx[0] = 0x61707865;
  ctx[1] = 0x3320646e;
  ctx[2] = 0x79622d32;
  ctx[3] = 0x6b206574;
  for (int i = 0; i < 8; ++i) ctx[4 + i] = load32_le(key + i * 4);
  ctx[12] = counter;
  for (int i = 0; i < 3; ++i) ctx[13 + i] = load32_le(nonce + i * 4);

  u8 block[64];
  while (len > 0) {
    u32 x[16];
    for (int i = 0; i < 16; ++i) x[i] = ctx[i];
    for (int r = 0; r < 10; ++r) {
      QR(x[0], x[4], x[8],  x[12]);
      QR(x[1], x[5], x[9],  x[13]);
      QR(x[2], x[6], x[10], x[14]);
      QR(x[3], x[7], x[11], x[15]);
      QR(x[0], x[5], x[10], x[15]);
      QR(x[1], x[6], x[11], x[12]);
      QR(x[2], x[7], x[8],  x[13]);
      QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; ++i) store32_le(block + i * 4, x[i] + ctx[i]);
    ctx[12]++;

    usz take = (len < 64) ? len : 64;
    for (usz i = 0; i < take; ++i) out[i] = (in ? in[i] : 0) ^ block[i];
    if (in) in += take;
    out += take;
    len -= take;
  }
}

String createIetfNonce(u64 nonce) {
  String buffer;
  u8 tmp[12];
  for (int i = 0; i < 4; ++i) tmp[i] = 0;
  for (int i = 0; i < 8; ++i) tmp[4 + i] = (u8)((nonce >> (i * 8)) & 0xFF);
  buffer.pushEach(tmp, 12);
  return buffer;
}

String streamXor(const String &key, const String &nonce, const String &text, int counter) {
  if (key.size() != 32 || nonce.size() < 12)
    return String();

  String result;
  if (text.size() == 0)
    return result;

  u8 *out = new u8[text.size()];
  const u8 *k = reinterpret_cast<const u8 *>(key.data());
  const u8 *n = reinterpret_cast<const u8 *>(nonce.data());
  const u8 *in = reinterpret_cast<const u8 *>(text.data());

  chacha20(out, in, text.size(), k, n, (u32)counter);
  result.pushEach(out, text.size());
  delete[] out;
  return result;
}

String streamXor(const String &key, u64 nonce, const String &text, int counter) {
  String n = createIetfNonce(nonce);
  return streamXor(key, n, text, counter);
}

String encrypt(const String &key, u64 nonce, const String &plaintext, int counter) {
  return streamXor(key, nonce, plaintext, counter);
}

String encrypt(const String &key, const String &nonce, const String &plaintext, int counter) {
  return streamXor(key, nonce, plaintext, counter);
}

String decrypt(const String &key, u64 nonce, const String &ciphertext, int counter) {
  return streamXor(key, nonce, ciphertext, counter);
}

String decrypt(const String &key, const String &nonce, const String &ciphertext, int counter) {
  return streamXor(key, nonce, ciphertext, counter);
}

} // namespace Sec
