/**
 * @file Random.cpp
 * @brief Implementation of random number generation utilities.
 */

#include "Xi/Xi.hpp"
#include "Xi/Random.hpp"

#if !defined(__KERNEL__) && !defined(XI_NO_STD)
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#if __has_include(<sys/mman.h>) && defined(__linux__)
#include <sys/mman.h>
#endif
#endif

#if defined(__KERNEL__)
#include <linux/random.h>
#endif

#if !defined(__KERNEL__)
#include <string.h>
#endif

#if defined(_WIN32)
extern "C" __declspec(dllimport) unsigned char __stdcall SystemFunction036(void* RandomBuffer, unsigned long RandomBufferLength);
#endif

namespace Xi {

alignas(64) u32 _randomPool[20] = {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
    0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac
};
bool _randomInitialized = false;
u32 _randomCounter = 0;

static inline u32 rotl32(u32 v, int n) {
  return (v << n) | (v >> (32 - n));
}

static inline void quarterRound(u32 &a, u32 &b, u32 &c, u32 &d) {
  a += b; d ^= a; d = rotl32(d, 16);
  c += d; b ^= c; b = rotl32(b, 12);
  a += b; d ^= a; d = rotl32(d, 8);
  c += d; b ^= c; b = rotl32(b, 7);
}

// Mixes the entire 20-word pool using a permutation round
static void advancePool() {
  _randomCounter++;
  _randomPool[16] += _randomCounter;
  _randomPool[17] ^= _randomPool[16];
  _randomPool[18] += _randomPool[17];
  _randomPool[19] ^= rotl32(_randomPool[18], 13);

  // Column rounds across 16 main words
  quarterRound(_randomPool[0], _randomPool[4], _randomPool[8],  _randomPool[12]);
  quarterRound(_randomPool[1], _randomPool[5], _randomPool[9],  _randomPool[13]);
  quarterRound(_randomPool[2], _randomPool[6], _randomPool[10], _randomPool[14]);
  quarterRound(_randomPool[3], _randomPool[7], _randomPool[11], _randomPool[15]);

  // Diagonal rounds with mixing from extra pool words
  quarterRound(_randomPool[0], _randomPool[5], _randomPool[10], _randomPool[15]);
  quarterRound(_randomPool[1], _randomPool[6], _randomPool[11], _randomPool[12]);
  quarterRound(_randomPool[2], _randomPool[7], _randomPool[8],  _randomPool[13]);
  quarterRound(_randomPool[3], _randomPool[4], _randomPool[9],  _randomPool[14]);

  _randomPool[0] ^= _randomPool[16];
  _randomPool[5] ^= _randomPool[17];
  _randomPool[10] ^= _randomPool[18];
  _randomPool[15] ^= _randomPool[19];
}

void randomSeed(u64 seed, bool overwrite) {
  if (!overwrite && _randomInitialized)
    return;

  u64 s = seed;
  for (int i = 0; i < 20; i++) {
    s += 0x9e3779b97f4a7c15ULL;
    u64 z = s;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    _randomPool[i] = (u32)(z ^ (z >> 31));
  }
  _randomCounter = 0;
  for (int i = 0; i < 4; i++) {
    advancePool();
  }
  _randomInitialized = true;
}

void randomSeed(bool overwrite) {
  if (!overwrite && _randomInitialized)
    return;

  bool filled = false;
#if defined(__KERNEL__)
  get_random_bytes(_randomPool, sizeof(_randomPool));
  filled = true;
#elif defined(ESP_PLATFORM)
  for (int i = 0; i < 20; i++)
    _randomPool[i] = esp_random();
  filled = true;
#elif defined(_WIN32)
  if (SystemFunction036(_randomPool, sizeof(_randomPool))) {
    filled = true;
  }
#elif defined(ARDUINO)
  u32 seed = 0;
  for (int i = 0; i < 16; i++) {
    seed = (seed << 2) | (analogRead(0) & 3);
  }
  randomSeed((u64)seed, overwrite);
  return;
#elif defined(__linux__) || defined(__APPLE__)
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    ssize_t n = read(fd, _randomPool, sizeof(_randomPool));
    close(fd);
    if (n == (ssize_t)sizeof(_randomPool)) {
      filled = true;
    }
  }
#endif

  if (filled) {
    _randomInitialized = true;
    _randomCounter = 0;
    advancePool();
  } else {
    // Fallback using time and memory address entropy
    u64 entropy = 0x9e3779b97f4a7c15ULL;
    struct timeval tv;
    if (gettimeofday(&tv, nullptr) == 0) {
      entropy ^= ((u64)tv.tv_sec << 32) | (u64)tv.tv_usec;
    }
    entropy ^= (u64)(uintptr_t)&_randomPool;
    randomSeed(entropy, overwrite);
  }

#if defined(__linux__) && __has_include(<sys/mman.h>)
  madvise(_randomPool, sizeof(_randomPool), MADV_WIPEONFORK);
#endif
}

u32 random() {
  if (!_randomInitialized) {
    randomSeed(false);
  }
  advancePool();
  return _randomPool[0] ^ _randomPool[12];
}

u32 random(u32 max) {
  if (max == 0) return 0;
  return random() % max;
}

i32 random(i32 min, i32 max) {
  if (min >= max) return min;
  return min + (i32)(random() % (u32)(max - min));
}

void randomFill(u8 *buffer, usz size) {
  if (!buffer || size == 0) return;
  if (!_randomInitialized) {
    randomSeed(false);
  }

  usz offset = 0;
  while (offset + 64 <= size) {
    advancePool();
    memcpy(buffer + offset, _randomPool, 64);
    offset += 64;
  }
  if (offset < size) {
    advancePool();
    memcpy(buffer + offset, _randomPool, size - offset);
  }
}

} // namespace Xi
