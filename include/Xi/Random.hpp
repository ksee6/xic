/**
 * @file Random.hpp
 * @brief Pseudo-random number generation utilities for the Xi framework.
 */

#ifndef XI_CORE_RANDOM_HPP
#define XI_CORE_RANDOM_HPP

#include "Xi.hpp"
#include "String.hpp"
#include "../Math/Random.hpp"

namespace Xi {

/**
 * @brief Fills a string with pseudo-random bytes.
 */
void randomFill(String &s, usz len = 0);

} // namespace Xi

#endif // XI_CORE_RANDOM_HPP