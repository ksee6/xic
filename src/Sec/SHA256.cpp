/**
 * @file SHA256.cpp
 * @brief SHA-256 implementation without standard library dependencies.
 */

#include "../../include/Sec/SHA256.hpp"

namespace Sec {

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

const u32 SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA256::SHA256() {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
    count = 0;
}

static inline u32 read32BE(const u8* p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static inline void write32BE(u8* p, u32 v) {
    p[0] = (u8)(v >> 24);
    p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >> 8);
    p[3] = (u8)v;
}

void SHA256::transform(const u8 block[64]) {
    u32 w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = read32BE(block + i * 4);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }

    u32 a = state[0];
    u32 b = state[1];
    u32 c = state[2];
    u32 d = state[3];
    u32 e = state[4];
    u32 f = state[5];
    u32 g = state[6];
    u32 h = state[7];

    for (int i = 0; i < 64; i++) {
        u32 t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
        u32 t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void SHA256::update(const void* data, usz len) {
    const u8* p = (const u8*)data;
    usz bufferIdx = (count / 8) % BlockSize;
    count += (u64)len * 8;

    usz partLen = BlockSize - bufferIdx;
    usz i = 0;

    if (len >= partLen) {
        for (usz j = 0; j < partLen; ++j) buffer[bufferIdx + j] = p[j];
        transform(buffer);
        for (i = partLen; i + BlockSize <= len; i += BlockSize) {
            transform(p + i);
        }
        bufferIdx = 0;
    }

    for (usz j = 0; j < len - i; ++j) buffer[bufferIdx + j] = p[i + j];
}

void SHA256::update(const String& str) {
    update(str.data(), str.length());
}

void SHA256::final(u8 digest[DigestSize]) {
    u8 finalCount[8];
    for (int i = 0; i < 8; i++) {
        finalCount[i] = (u8)((count >> ((7 - i) * 8)) & 0xff);
    }

    u8 pad[64];
    pad[0] = 0x80;
    for (int i = 1; i < 64; ++i) pad[i] = 0;

    usz bufferIdx = (count / 8) % BlockSize;
    usz padLen = (bufferIdx < 56) ? (56 - bufferIdx) : (120 - bufferIdx);
    update(pad, padLen);
    update(finalCount, 8);

    for (int i = 0; i < 8; i++) {
        write32BE(digest + i * 4, state[i]);
    }
}

String SHA256::final() {
    u8 digest[DigestSize];
    final(digest);
    String res;
    res.pushEach(digest, DigestSize);
    return res;
}

String SHA256::hash(const String& input) {
    SHA256 ctx;
    ctx.update(input);
    return ctx.final();
}

String SHA256::hash(const void* data, usz len) {
    SHA256 ctx;
    ctx.update(data, len);
    return ctx.final();
}

void SHA256::hash(const void* data, usz len, u8 digest[DigestSize]) {
    SHA256 ctx;
    ctx.update(data, len);
    ctx.final(digest);
}

} // namespace Sec
