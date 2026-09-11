#ifndef XI_MATH_RANDOM_HPP
#define XI_MATH_RANDOM_HPP

#include "../Xi/Xi.hpp"

namespace Math {

using namespace Xi;

/**
 * @brief Generates a random float in range [0.0, 1.0].
 */
inline f32 randomFloat() {
  return (f32)random(0xFFFFFFFFU) / 4294967295.0f;
}

/**
 * @brief Generates a random double in range [0.0, 1.0].
 */
inline f64 randomDouble() {
  u64 r = ((u64)random(0xFFFFFFFFU) << 32) | (u64)random(0xFFFFFFFFU);
  return (f64)r / 18446744073709551615.0;
}

} // namespace Math

namespace Xi {
  using Math::randomFloat;
  using Math::randomDouble;
}

#endif // XI_MATH_RANDOM_HPP
