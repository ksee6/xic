/**
 * @file Poly1305.cpp
 * @brief Standalone, high-speed RFC 8439 Poly1305 MAC implementation.
 */

#include "../../include/Sec/Poly1305.hpp"

namespace Sec {

using Xi::u128;

static inline u64 load64_le(const u8 *p) {
  return ((u64)p[0]) | ((u64)p[1] << 8) | ((u64)p[2] << 16) | ((u64)p[3] << 24) |
         ((u64)p[4] << 32) | ((u64)p[5] << 40) | ((u64)p[6] << 48) | ((u64)p[7] << 56);
}

static inline void store64_le(u8 *p, u64 v) {
  p[0] = (u8)v;
  p[1] = (u8)(v >> 8);
  p[2] = (u8)(v >> 16);
  p[3] = (u8)(v >> 24);
  p[4] = (u8)(v >> 32);
  p[5] = (u8)(v >> 40);
  p[6] = (u8)(v >> 48);
  p[7] = (u8)(v >> 56);
}

void poly1305(u8 tag[16], const u8 *msg, usz len, const u8 key[32]) {
  u64 r0 = load64_le(key) & 0x0ffffffc0fffffffULL;
  u64 r1 = load64_le(key + 8) & 0x0ffffffc0ffffffcULL;
  u64 s0 = load64_le(key + 16);
  u64 s1 = load64_le(key + 24);

  u64 r1_prime = (r1 >> 2) * 5;

  u64 h0 = 0, h1 = 0, h2 = 0;

  while (len > 0) {
    usz take = (len < 16) ? len : 16;
    u8 block[17];
    for (int i = 0; i < 17; ++i) block[i] = 0;
    for (usz i = 0; i < take; ++i) block[i] = msg[i];
    block[take] = 1;

    u64 b0 = load64_le(block);
    u64 b1 = load64_le(block + 8);
    u64 b2 = block[16];

    u128 c0 = (u128)h0 + b0;
    h0 = (u64)c0;
    u128 c1 = (u128)h1 + b1 + (u64)(c0 >> 64);
    h1 = (u64)c1;
    h2 += b2 + (u64)(c1 >> 64);

    u128 d0 = (u128)h0 * r0 + (u128)h1 * r1_prime;
    u128 d1 = (u128)h0 * r1 + (u128)h1 * r0 + (u128)h2 * r1_prime;
    u128 d2 = (u128)h2 * r0;

    u128 d1_hi = (d1 >> 64) + d2;
    u64 d1_hi_64 = (u64)d1_hi;
    u128 c = (u128)d0 + (u128)(d1_hi_64 >> 2) * 5;
    h0 = (u64)c;
    u128 d1_lo = (d1 & 0xffffffffffffffffULL) + (c >> 64);
    h1 = (u64)d1_lo;
    h2 = (d1_hi_64 & 3) + (u64)(d1_lo >> 64);

    if (h2 >= 4) {
      u64 q = h2 >> 2;
      h2 &= 3;
      u128 c2 = (u128)h0 + (u128)q * 5;
      h0 = (u64)c2;
      h1 += (u64)(c2 >> 64);
    }

    msg += take;
    len -= take;
  }

  u64 q = (h2 >> 2);
  h2 &= 3;
  u128 c = (u128)h0 + (u128)q * 5;
  h0 = (u64)c;
  u128 c1 = (u128)h1 + (u64)(c >> 64);
  h1 = (u64)c1;
  h2 += (u64)(c1 >> 64);
  q = (h2 >> 2);
  h2 &= 3;
  c = (u128)h0 + (u128)q * 5;
  h0 = (u64)c;
  h1 += (u64)(c >> 64);

  u128 sub0 = (u128)h0 + 5;
  u64 g0 = (u64)sub0;
  u128 sub1 = (u128)h1 + (u64)(sub0 >> 64);
  u64 g1 = (u64)sub1;
  u64 g2 = h2 + (u64)(sub1 >> 64);

  if (g2 >= 4) {
    h0 = g0;
    h1 = g1;
  }

  u128 fin0 = (u128)h0 + s0;
  u128 fin1 = (u128)h1 + s1 + (u64)(fin0 >> 64);

  store64_le(tag, (u64)fin0);
  store64_le(tag + 8, (u64)fin1);
}

String createPoly1305Key(const String &key, u64 nonce) {
  String n = createIetfNonce(nonce);
  return createPoly1305Key(key, n);
}

String createPoly1305Key(const String &key, const String &nonce) {
  if (key.size() != 32 || nonce.size() < 12)
    return String();

  String zero32;
  u8 zeros[32];
  for (int i = 0; i < 32; ++i) zeros[i] = 0;
  zero32.pushEach(zeros, 32);

  return streamXor(key, nonce, zero32, 0);
}

String Poly1305::hash(const String &key, const String &message) {
  if (key.size() != 32)
    return String();

  u8 tag[16];
  const u8 *k = reinterpret_cast<const u8 *>(key.data());
  const u8 *m = reinterpret_cast<const u8 *>(message.data());
  poly1305(tag, m, message.size(), k);

  String res;
  res.pushEach(tag, 16);
  return res;
}

bool Poly1305::verify(const String &key, const String &message, const String &tag) {
  if (tag.size() != 16)
    return false;

  String computed = Poly1305::hash(key, message);
  return tag.constantTimeEquals(computed, 16);
}

} // namespace Sec
