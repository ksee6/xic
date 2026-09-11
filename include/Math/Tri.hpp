#ifndef XI_MATH_TRI_HPP
#define XI_MATH_TRI_HPP

#include "../Xi/Xi.hpp"

namespace Math {

using namespace Xi;

#if defined(_MSC_VER) && !defined(__clang__)
#include <math.h>
#define SC_TRI(name, func) inline f32 name(f32 x) { return func(x); }
SC_TRI(sin, ::sinf)
SC_TRI(cos, ::cosf)
SC_TRI(tan, ::tanf)
SC_TRI(asin, ::asinf)
SC_TRI(acos, ::acosf)
SC_TRI(atan, ::atanf)
SC_TRI(sinh, ::sinhf)
SC_TRI(cosh, ::coshf)
SC_TRI(tanh, ::tanhf)
SC_TRI(asinh, ::asinhf)
SC_TRI(acosh, ::acoshf)
SC_TRI(atanh, ::atanhf)
inline f32 atan2(f32 y, f32 x) { return ::atan2f(y, x); }
#else
#define SC_TRI(name, func) inline f32 name(f32 x) { return func(x); }
SC_TRI(sin, __builtin_sinf)
SC_TRI(cos, __builtin_cosf)
SC_TRI(tan, __builtin_tanf)
SC_TRI(asin, __builtin_asinf)
SC_TRI(acos, __builtin_acosf)
SC_TRI(atan, __builtin_atanf)
SC_TRI(sinh, __builtin_sinhf)
SC_TRI(cosh, __builtin_coshf)
SC_TRI(tanh, __builtin_tanhf)
SC_TRI(asinh, __builtin_asinhf)
SC_TRI(acosh, __builtin_acoshf)
SC_TRI(atanh, __builtin_atanhf)
inline f32 atan2(f32 y, f32 x) { return __builtin_atan2f(y, x); }
#endif

// Generic overloads for structs/vectors
#define MATH_TRI_OVERLOAD(name) \
  template <typename T> inline T name(const T &v) { \
    T res = v; \
    f32 *pr = reinterpret_cast<f32 *>(&res); \
    const f32 *pv = reinterpret_cast<const f32 *>(&v); \
    for (usz i = 0; i < sizeof(T) / sizeof(f32); ++i) \
      pr[i] = ::Math::name(pv[i]); \
    return res; \
  }

MATH_TRI_OVERLOAD(sin)
MATH_TRI_OVERLOAD(cos)
MATH_TRI_OVERLOAD(tan)
MATH_TRI_OVERLOAD(asin)
MATH_TRI_OVERLOAD(acos)
MATH_TRI_OVERLOAD(atan)
MATH_TRI_OVERLOAD(sinh)
MATH_TRI_OVERLOAD(cosh)
MATH_TRI_OVERLOAD(tanh)
MATH_TRI_OVERLOAD(asinh)
MATH_TRI_OVERLOAD(acosh)
MATH_TRI_OVERLOAD(atanh)

} // namespace Math

namespace Xi {
  using Math::sin;
  using Math::cos;
  using Math::tan;
  using Math::asin;
  using Math::acos;
  using Math::atan;
  using Math::atan2;
  using Math::sinh;
  using Math::cosh;
  using Math::tanh;
  using Math::asinh;
  using Math::acosh;
  using Math::atanh;
}

#endif // XI_MATH_TRI_HPP
