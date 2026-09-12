/**
 * @file Blake2b.cpp
 * @brief Standalone, high-speed BLAKE2b and HKDF-BLAKE2b implementation.
 */

#include "../../include/Sec/Blake2b.hpp"
#include "../../include/Xi/Xi.hpp"

namespace Sec {

static const u64 blake2b_iv[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const u8 blake2b_sigma[12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static void blake2b_compress(Blake2bCtx *ctx, const u8 block[128]) {
  u64 m[16];
  for (int i = 0; i < 16; ++i) m[i] = load64_le(block + i * 8);

  u64 v[16];
  for (int i = 0; i < 8; ++i) v[i] = ctx->h[i];
  v[8]  = blake2b_iv[0];
  v[9]  = blake2b_iv[1];
  v[10] = blake2b_iv[2];
  v[11] = blake2b_iv[3];
  v[12] = blake2b_iv[4] ^ ctx->t[0];
  v[13] = blake2b_iv[5] ^ ctx->t[1];
  v[14] = blake2b_iv[6] ^ ctx->f[0];
  v[15] = blake2b_iv[7] ^ ctx->f[1];

#define G(r, i, a, b, c, d) do {   a = a + b + m[blake2b_sigma[r][2*i]];   d = rotr64(d ^ a, 32);   c = c + d;   b = rotr64(b ^ c, 24);   a = a + b + m[blake2b_sigma[r][2*i + 1]];   d = rotr64(d ^ a, 16);   c = c + d;   b = rotr64(b ^ c, 63); } while (0)

  for (int r = 0; r < 12; ++r) {
    G(r, 0, v[0], v[4], v[8],  v[12]);
    G(r, 1, v[1], v[5], v[9],  v[13]);
    G(r, 2, v[2], v[6], v[10], v[14]);
    G(r, 3, v[3], v[7], v[11], v[15]);
    G(r, 4, v[0], v[5], v[10], v[15]);
    G(r, 5, v[1], v[6], v[11], v[12]);
    G(r, 6, v[2], v[7], v[8],  v[13]);
    G(r, 7, v[3], v[4], v[9],  v[14]);
  }
#undef G

  for (int i = 0; i < 8; ++i) ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_increment_counter(Blake2bCtx *ctx, u64 inc) {
  ctx->t[0] += inc;
  if (ctx->t[0] < inc) ctx->t[1]++;
}

void blake2bInit(Blake2bCtx *ctx, usz outlen, const void *key, usz keylen) {
  for (int i = 0; i < 8; ++i) ctx->h[i] = blake2b_iv[i];
  ctx->h[0] ^= 0x01010000 ^ ((u64)keylen << 8) ^ (u64)outlen;
  ctx->t[0] = ctx->t[1] = 0;
  ctx->f[0] = ctx->f[1] = 0;
  ctx->buflen = 0;
  ctx->outlen = outlen;
  for (int i = 0; i < 128; ++i) ctx->buf[i] = 0;

  if (keylen > 0) {
    u8 block[128];
    for (int i = 0; i < 128; ++i) block[i] = 0;
    const u8 *k = (const u8*)key;
    for (usz i = 0; i < keylen; ++i) block[i] = k[i];
    blake2b_increment_counter(ctx, 128);
    blake2b_compress(ctx, block);
  }
}

void blake2bUpdate(Blake2bCtx *ctx, const void *pin, usz inlen) {
  const u8 *in = (const u8*)pin;
  while (inlen > 0) {
    if (ctx->buflen == 128) {
      blake2b_increment_counter(ctx, 128);
      blake2b_compress(ctx, ctx->buf);
      ctx->buflen = 0;
    }
    usz want = 128 - ctx->buflen;
    usz take = (inlen < want) ? inlen : want;
    for (usz i = 0; i < take; ++i) ctx->buf[ctx->buflen + i] = in[i];
    ctx->buflen += take;
    in += take;
    inlen -= take;
  }
}

void blake2bFinal(Blake2bCtx *ctx, void *pout) {
  blake2b_increment_counter(ctx, ctx->buflen);
  ctx->f[0] = ~0ULL;
  for (usz i = ctx->buflen; i < 128; ++i) ctx->buf[i] = 0;
  blake2b_compress(ctx, ctx->buf);

  u8 outbuf[64];
  for (int i = 0; i < 8; ++i) store64_le(outbuf + i * 8, ctx->h[i]);
  u8 *dst = (u8*)pout;
  for (usz i = 0; i < ctx->outlen; ++i) dst[i] = outbuf[i];
}

String B2B::hash(const String &input, int length, const String &key) {
  return hash(input.data(), input.size(), length, key);
}

String B2B::hash(const void *data, usz len, int length, const String &key) {
  if (length > 64 || length < 1)
    return String();

  Blake2bCtx ctx;
  const void *keyData = key.isEmpty() ? nullptr : key.data();
  blake2bInit(&ctx, (usz)length, keyData, key.size());
  if (data && len > 0) {
    blake2bUpdate(&ctx, data, len);
  }
  u8 buf[64];
  blake2bFinal(&ctx, buf);

  String result;
  result.pushEach(buf, (usz)length);
  return result;
}

String B2B::hkdf(const String &secret, const String &salt, const String &info, int length) {
  const int hashLen = 64;
  if (length <= 0 || length > 255 * hashLen)
    return String();

  // 1. Extract: PRK = BLAKE2b(secret, key = salt)
  String prk = B2B::hash(secret, hashLen, salt);

  // 2. Expand: T(i) = BLAKE2b(T(i-1) || info || counter, key = PRK)
  int numBlocks = (length + hashLen - 1) / hashLen;
  String okm;
  String t;

  for (int i = 1; i <= numBlocks; i++) {
    String expandInput;
    expandInput += t;
    expandInput += info;
    expandInput.push((u8)i);
    t = B2B::hash(expandInput, hashLen, prk);
    okm += t;
  }

  return okm.begin(0, length);
}

String B2B::hkdf(const String &secret, const String &info, int length) {
  return hkdf(secret, String(), info, length);
}

} // namespace Sec

