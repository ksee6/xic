#ifndef XI_MATH_STAT_HPP
#define XI_MATH_STAT_HPP

#include "../Xi/Xi.hpp"
#include "../Xi/Array.hpp"

namespace Math {

using namespace Xi;

/** @brief Sum of elements in a POD struct. */
template <typename T> inline f32 sum(const T &v) {
  const f32 *p = reinterpret_cast<const f32 *>(&v);
  f32 s = 0;
  for (usz i = 0; i < sizeof(T) / sizeof(f32); ++i)
    s += p[i];
  return s;
}

/** @brief Mean of elements in a POD struct. */
template <typename T> inline f32 mean(const T &v) {
  return sum(v) / (f32)(sizeof(T) / sizeof(f32));
}

/** @brief Sum of elements in an Array. */
template <typename T> f32 sum(const Array<T> &a) {
  f32 s = 0;
  usz n = a.size();
  const T *d = a.data();
  _Pragma("omp simd") for (usz i = 0; i < n; ++i) s += ::Math::sum(d[i]);
  return s;
}

/** @brief Mean of elements in an Array. */
template <typename T> f32 mean(const Array<T> &a) {
  usz n = a.size();
  return (n == 0) ? 0 : sum(a) / (f32)n;
}

/** @brief Variance of elements in an Array. */
template <typename T> f32 var(const Array<T> &a) {
  usz n = a.size();
  if (n == 0)
    return 0;
  f32 m = mean(a);
  f32 v = 0;
  const T *d = a.data();
  for (usz i = 0; i < n; ++i) {
    f32 diff = (f32)d[i] - m;
    v += diff * diff;
  }
  return v / (f32)n;
}

/** @brief Standard deviation of elements in an Array. */
template <typename T> f32 std(const Array<T> &a) { return ::Math::sqrt(var(a)); }

// Explicit specializations for Array<f32> (Tensor)
template <> f32 sum<f32>(const Array<f32> &a);
template <> f32 mean<f32>(const Array<f32> &a);
template <> f32 var<f32>(const Array<f32> &a);
template <> f32 std<f32>(const Array<f32> &a);

} // namespace Math

namespace Xi {
  using Math::sum;
  using Math::mean;
  using Math::var;
  using Math::std;
}

#endif // XI_MATH_STAT_HPP
