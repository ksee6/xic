/**
 * @file X25519.cpp
 * @brief High-performance standalone implementation of X25519 Diffie-Hellman.
 */

#include "../../include/Sec/X25519.hpp"
#include "../../include/Xi/Xi.hpp"

namespace Sec {

#define FOR(i, start, end) for (usz i = (start); i < (end); i++)
#define ZERO(p, n) do { for (usz _i = 0; _i < (n); _i++) (p)[_i] = 0; } while (0)
#define COPY(d, s, n) do { for (usz _i = 0; _i < (n); _i++) (d)[_i] = (s)[_i]; } while (0)
#define WIPE_BUFFER(b) do { volatile u8 *_p = (volatile u8*)(b); for (usz _i = 0; _i < sizeof(b); _i++) _p[_i] = 0; } while (0)

typedef i32 fe[10];

static const fe fe_one  = {1};
static const fe sqrtm1 = {
	34513072, 25610706, 9377949, 3500415, 12389472,
	33281959, 41962654, 31548777, 326685, 11406482
};

static void fe_0(fe h) {           ZERO(h  , 10); }
static void fe_1(fe h) { h[0] = 1; ZERO(h+1,  9); }

static void fe_copy(fe h,const fe f           ){FOR(i,0,10) h[i] =  f[i];      }
static void fe_neg (fe h,const fe f           ){FOR(i,0,10) h[i] = -f[i];      }
static void fe_add (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] + g[i];}
static void fe_sub (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] - g[i];}

static void fe_cswap(fe f, fe g, int b)
{
	i32 mask = -b;
	FOR (i, 0, 10) {
		i32 x = (f[i] ^ g[i]) & mask;
		f[i] = f[i] ^ x;
		g[i] = g[i] ^ x;
	}
}

static void fe_ccopy(fe f, const fe g, int b)
{
	i32 mask = -b;
	FOR (i, 0, 10) {
		i32 x = (f[i] ^ g[i]) & mask;
		f[i] = f[i] ^ x;
	}
}

#define FE_CARRY	\
	i64 c; \
	c = (t0 + ((i64)1<<25)) >> 26;  t0 -= c * ((i64)1 << 26);  t1 += c; \
	c = (t4 + ((i64)1<<25)) >> 26;  t4 -= c * ((i64)1 << 26);  t5 += c; \
	c = (t1 + ((i64)1<<24)) >> 25;  t1 -= c * ((i64)1 << 25);  t2 += c; \
	c = (t5 + ((i64)1<<24)) >> 25;  t5 -= c * ((i64)1 << 25);  t6 += c; \
	c = (t2 + ((i64)1<<25)) >> 26;  t2 -= c * ((i64)1 << 26);  t3 += c; \
	c = (t6 + ((i64)1<<25)) >> 26;  t6 -= c * ((i64)1 << 26);  t7 += c; \
	c = (t3 + ((i64)1<<24)) >> 25;  t3 -= c * ((i64)1 << 25);  t4 += c; \
	c = (t7 + ((i64)1<<24)) >> 25;  t7 -= c * ((i64)1 << 25);  t8 += c; \
	c = (t4 + ((i64)1<<25)) >> 26;  t4 -= c * ((i64)1 << 26);  t5 += c; \
	c = (t8 + ((i64)1<<25)) >> 26;  t8 -= c * ((i64)1 << 26);  t9 += c; \
	c = (t9 + ((i64)1<<24)) >> 25;  t9 -= c * ((i64)1 << 25);  t0 += c * 19; \
	c = (t0 + ((i64)1<<25)) >> 26;  t0 -= c * ((i64)1 << 26);  t1 += c; \
	h[0]=(i32)t0;  h[1]=(i32)t1;  h[2]=(i32)t2;  h[3]=(i32)t3;  h[4]=(i32)t4; \
	h[5]=(i32)t5;  h[6]=(i32)t6;  h[7]=(i32)t7;  h[8]=(i32)t8;  h[9]=(i32)t9

static void fe_frombytes(fe h, const u8 s[32])
{
	u32 mask = 0xffffff >> 1;
	i64 t0 =  load32_le(s);
	i64 t1 =  load24_le(s +  4) << 6;
	i64 t2 =  load24_le(s +  7) << 5;
	i64 t3 =  load24_le(s + 10) << 3;
	i64 t4 =  load24_le(s + 13) << 2;
	i64 t5 =  load32_le(s + 16);
	i64 t6 =  load24_le(s + 20) << 7;
	i64 t7 =  load24_le(s + 23) << 5;
	i64 t8 =  load24_le(s + 26) << 4;
	i64 t9 = (load24_le(s + 29) & mask) << 2;
	FE_CARRY;
}

static void fe_tobytes(u8 s[32], const fe h)
{
	i32 t[10];
	COPY(t, h, 10);
	i32 q = (19 * t[9] + (((i32) 1) << 24)) >> 25;
	FOR (i, 0, 5) {
		q += t[2*i  ]; q >>= 26;
		q += t[2*i+1]; q >>= 25;
	}
	q *= 19;
	FOR (i, 0, 5) {
		t[i*2  ] += q;  q = t[i*2  ] >> 26;  t[i*2  ] -= q * ((i32)1 << 26);
		t[i*2+1] += q;  q = t[i*2+1] >> 25;  t[i*2+1] -= q * ((i32)1 << 25);
	}

	store32_le(s +  0, ((u32)t[0] >>  0) | ((u32)t[1] << 26));
	store32_le(s +  4, ((u32)t[1] >>  6) | ((u32)t[2] << 19));
	store32_le(s +  8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
	store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] <<  6));
	store32_le(s + 16, ((u32)t[5] >>  0) | ((u32)t[6] << 25));
	store32_le(s + 20, ((u32)t[6] >>  7) | ((u32)t[7] << 19));
	store32_le(s + 24, ((u32)t[7] >> 13) | ((u32)t[8] << 12));
	store32_le(s + 28, ((u32)t[8] >> 20) | ((u32)t[9] <<  6));

	WIPE_BUFFER(t);
}

static void fe_mul_small(fe h, const fe f, i32 g)
{
	i64 t0 = f[0] * (i64) g;  i64 t1 = f[1] * (i64) g;
	i64 t2 = f[2] * (i64) g;  i64 t3 = f[3] * (i64) g;
	i64 t4 = f[4] * (i64) g;  i64 t5 = f[5] * (i64) g;
	i64 t6 = f[6] * (i64) g;  i64 t7 = f[7] * (i64) g;
	i64 t8 = f[8] * (i64) g;  i64 t9 = f[9] * (i64) g;
	FE_CARRY;
}

static void fe_mul(fe h, const fe f, const fe g)
{
	i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
	i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
	i32 g0 = g[0]; i32 g1 = g[1]; i32 g2 = g[2]; i32 g3 = g[3]; i32 g4 = g[4];
	i32 g5 = g[5]; i32 g6 = g[6]; i32 g7 = g[7]; i32 g8 = g[8]; i32 g9 = g[9];
	i32 F1 = f1*2; i32 F3 = f3*2; i32 F5 = f5*2; i32 F7 = f7*2; i32 F9 = f9*2;
	i32 G1 = g1*19;  i32 G2 = g2*19;  i32 G3 = g3*19;
	i32 G4 = g4*19;  i32 G5 = g5*19;  i32 G6 = g6*19;
	i32 G7 = g7*19;  i32 G8 = g8*19;  i32 G9 = g9*19;

	i64 t0 = f0*(i64)g0 + F1*(i64)G9 + f2*(i64)G8 + F3*(i64)G7 + f4*(i64)G6
	       + F5*(i64)G5 + f6*(i64)G4 + F7*(i64)G3 + f8*(i64)G2 + F9*(i64)G1;
	i64 t1 = f0*(i64)g1 + f1*(i64)g0 + f2*(i64)G9 + f3*(i64)G8 + f4*(i64)G7
	       + f5*(i64)G6 + f6*(i64)G5 + f7*(i64)G4 + f8*(i64)G3 + f9*(i64)G2;
	i64 t2 = f0*(i64)g2 + F1*(i64)g1 + f2*(i64)g0 + F3*(i64)G9 + f4*(i64)G8
	       + F5*(i64)G7 + f6*(i64)G6 + F7*(i64)G5 + f8*(i64)G4 + F9*(i64)G3;
	i64 t3 = f0*(i64)g3 + f1*(i64)g2 + f2*(i64)g1 + f3*(i64)g0 + f4*(i64)G9
	       + f5*(i64)G8 + f6*(i64)G7 + f7*(i64)G6 + f8*(i64)G5 + f9*(i64)G4;
	i64 t4 = f0*(i64)g4 + F1*(i64)g3 + f2*(i64)g2 + F3*(i64)g1 + f4*(i64)g0
	       + F5*(i64)G9 + f6*(i64)G8 + F7*(i64)G7 + f8*(i64)G6 + F9*(i64)G5;
	i64 t5 = f0*(i64)g5 + f1*(i64)g4 + f2*(i64)g3 + f3*(i64)g2 + f4*(i64)g1
	       + f5*(i64)g0 + f6*(i64)G9 + f7*(i64)G8 + f8*(i64)G7 + f9*(i64)G6;
	i64 t6 = f0*(i64)g6 + F1*(i64)g5 + f2*(i64)g4 + F3*(i64)g3 + f4*(i64)g2
	       + F5*(i64)g1 + f6*(i64)g0 + F7*(i64)G9 + f8*(i64)G8 + F9*(i64)G7;
	i64 t7 = f0*(i64)g7 + f1*(i64)g6 + f2*(i64)g5 + f3*(i64)g4 + f4*(i64)g3
	       + f5*(i64)g2 + f6*(i64)g1 + f7*(i64)g0 + f8*(i64)G9 + f9*(i64)G8;
	i64 t8 = f0*(i64)g8 + F1*(i64)g7 + f2*(i64)g6 + F3*(i64)g5 + f4*(i64)g4
	       + F5*(i64)g3 + f6*(i64)g2 + F7*(i64)g1 + f8*(i64)g0 + F9*(i64)G9;
	i64 t9 = f0*(i64)g9 + f1*(i64)g8 + f2*(i64)g7 + f3*(i64)g6 + f4*(i64)g5
	       + f5*(i64)g4 + f6*(i64)g3 + f7*(i64)g2 + f8*(i64)g1 + f9*(i64)g0;

	FE_CARRY;
}

static void fe_sq(fe h, const fe f)
{
	i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
	i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
	i32 f0_2  = f0*2;   i32 f1_2  = f1*2;   i32 f2_2  = f2*2;   i32 f3_2 = f3*2;
	i32 f4_2  = f4*2;   i32 f5_2  = f5*2;   i32 f6_2  = f6*2;   i32 f7_2 = f7*2;
	i32 f5_38 = f5*38;  i32 f6_19 = f6*19;  i32 f7_38 = f7*38;
	i32 f8_19 = f8*19;  i32 f9_38 = f9*38;

	i64 t0 = f0  *(i64)f0    + f1_2*(i64)f9_38 + f2_2*(i64)f8_19
	       + f3_2*(i64)f7_38 + f4_2*(i64)f6_19 + f5  *(i64)f5_38;
	i64 t1 = f0_2*(i64)f1    + f2  *(i64)f9_38 + f3_2*(i64)f8_19
	       + f4  *(i64)f7_38 + f5_2*(i64)f6_19;
	i64 t2 = f0_2*(i64)f2    + f1_2*(i64)f1    + f3_2*(i64)f9_38
	       + f4_2*(i64)f8_19 + f5_2*(i64)f7_38 + f6  *(i64)f6_19;
	i64 t3 = f0_2*(i64)f3    + f1_2*(i64)f2    + f4  *(i64)f9_38
	       + f5_2*(i64)f8_19 + f6  *(i64)f7_38;
	i64 t4 = f0_2*(i64)f4    + f1_2*(i64)f3_2  + f2  *(i64)f2
	       + f5_2*(i64)f9_38 + f6_2*(i64)f8_19 + f7  *(i64)f7_38;
	i64 t5 = f0_2*(i64)f5    + f1_2*(i64)f4    + f2_2*(i64)f3
	       + f6  *(i64)f9_38 + f7_2*(i64)f8_19;
	i64 t6 = f0_2*(i64)f6    + f1_2*(i64)f5_2  + f2_2*(i64)f4
	       + f3_2*(i64)f3    + f7_2*(i64)f9_38 + f8  *(i64)f8_19;
	i64 t7 = f0_2*(i64)f7    + f1_2*(i64)f6    + f2_2*(i64)f5
	       + f3_2*(i64)f4    + f8  *(i64)f9_38;
	i64 t8 = f0_2*(i64)f8    + f1_2*(i64)f7_2  + f2_2*(i64)f6
	       + f3_2*(i64)f5_2  + f4  *(i64)f4    + f9  *(i64)f9_38;
	i64 t9 = f0_2*(i64)f9    + f1_2*(i64)f8    + f2_2*(i64)f7
	       + f3_2*(i64)f6    + f4  *(i64)f5_2;

	FE_CARRY;
}

static int fe_isequal(const fe f, const fe g)
{
	u8 fs[32], gs[32];
	fe_tobytes(fs, f);
	fe_tobytes(gs, g);
	u32 diff = 0;
	for (int i = 0; i < 32; ++i) diff |= (u32)(fs[i] ^ gs[i]);
	WIPE_BUFFER(fs);
	WIPE_BUFFER(gs);
	return (diff == 0) ? 1 : 0;
}

static int invsqrt(fe isr, const fe x)
{
	fe t0, t1, t2;

	fe_sq(t0, x);
	fe_sq(t1,t0);                     fe_sq(t1, t1);    fe_mul(t1, x, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t0, t0);                                      fe_mul(t0, t1, t0);
	fe_sq(t1, t0);  FOR (i, 1,   5) { fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
	fe_sq(t1, t0);  FOR (i, 1,  10) { fe_sq(t1, t1); }  fe_mul(t1, t1, t0);
	fe_sq(t2, t1);  FOR (i, 1,  20) { fe_sq(t2, t2); }  fe_mul(t1, t2, t1);
	fe_sq(t1, t1);  FOR (i, 1,  10) { fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
	fe_sq(t1, t0);  FOR (i, 1,  50) { fe_sq(t1, t1); }  fe_mul(t1, t1, t0);
	fe_sq(t2, t1);  FOR (i, 1, 100) { fe_sq(t2, t2); }  fe_mul(t1, t2, t1);
	fe_sq(t1, t1);  FOR (i, 1,  50) { fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
	fe_sq(t0, t0);  FOR (i, 1,   2) { fe_sq(t0, t0); }  fe_mul(t0, t0, x);

	i32 *quartic = t1;
	fe_sq (quartic, t0);
	fe_mul(quartic, quartic, x);

	i32 *check = t2;
	fe_0  (check);          int z0 = fe_isequal(x      , check);
	fe_1  (check);          int p1 = fe_isequal(quartic, check);
	fe_neg(check, check );  int m1 = fe_isequal(quartic, check);
	fe_neg(check, sqrtm1);  int ms = fe_isequal(quartic, check);

	fe_mul(isr, t0, sqrtm1);
	fe_ccopy(isr, t0, 1 - (m1 | ms));

	WIPE_BUFFER(t0);
	WIPE_BUFFER(t1);
	WIPE_BUFFER(t2);
	return p1 | m1 | z0;
}

static void fe_invert(fe out, const fe x)
{
	fe tmp;
	fe_sq(tmp, x);
	invsqrt(tmp, tmp);
	fe_sq(tmp, tmp);
	fe_mul(out, tmp, x);
	WIPE_BUFFER(tmp);
}

static void crypto_eddsa_trim_scalar(u8 out[32], const u8 in[32])
{
	COPY(out, in, 32);
	out[ 0] &= 248;
	out[31] &= 127;
	out[31] |= 64;
}

static int scalar_bit(const u8 s[32], int i)
{
	if (i < 0) { return 0; }
	return (s[i >> 3] >> (i & 7)) & 1;
}

static void scalarmult(u8 q[32], const u8 scalar[32], const u8 p[32], int nb_bits)
{
	fe x1, x2, z2, x3, z3, t0, t1;
	fe_frombytes(x1, p);
	fe_1(x2);
	fe_0(z2);
	fe_copy(x3, x1);
	fe_1(z3);

	int swap = 0;
	for (int pos = nb_bits - 1; pos >= 0; --pos) {
		int b = scalar_bit(scalar, pos);
		swap ^= b;
		fe_cswap(x2, x3, swap);
		fe_cswap(z2, z3, swap);
		swap = b;

		fe_sub(t0, x3, z3);
		fe_sub(t1, x2, z2);
		fe_add(x2, x2, z2);
		fe_add(z2, x3, z3);
		fe_mul(z3, t0, x2);
		fe_mul(z2, z2, t1);
		fe_sq (t0, t1    );
		fe_sq (t1, x2    );
		fe_add(x3, z3, z2);
		fe_sub(z2, z3, z2);
		fe_mul(x2, t1, t0);
		fe_sub(t1, t1, t0);
		fe_sq (z2, z2    );
		fe_mul_small(z3, t1, 121666);
		fe_sq (x3, x3    );
		fe_add(t0, t0, z3);
		fe_mul(z3, x1, z2);
		fe_mul(z2, t1, t0);
	}
	fe_cswap(x2, x3, swap);
	fe_cswap(z2, z3, swap);

	fe_invert(z2, z2);
	fe_mul(x2, x2, z2);
	fe_tobytes(q, x2);

	WIPE_BUFFER(x1);
	WIPE_BUFFER(x2);  WIPE_BUFFER(z2);  WIPE_BUFFER(t0);
	WIPE_BUFFER(x3);  WIPE_BUFFER(z3);  WIPE_BUFFER(t1);
}

static void crypto_x25519(u8 raw_shared_secret[32], const u8 your_secret_key[32], const u8 their_public_key[32])
{
	u8 e[32];
	crypto_eddsa_trim_scalar(e, your_secret_key);
	scalarmult(raw_shared_secret, e, their_public_key, 255);
	WIPE_BUFFER(e);
}

static void crypto_x25519_public_key(u8 public_key[32], const u8 secret_key[32])
{
	static const u8 base_point[32] = {9};
	crypto_x25519(public_key, secret_key, base_point);
}

namespace X {

String& clamp(String &privateKey) {
  if (privateKey.size() >= 32) {
    u8 *k = reinterpret_cast<u8 *>(privateKey.data());
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;
  }
  return privateKey;
}

String clamp(const String &privateKey) {
  String copy = privateKey;
  clamp(copy);
  return copy;
}

String generateKey() {
  String secret;
  for (int i = 0; i < 32; ++i) secret.push(0);
  Xi::randomFill(reinterpret_cast<u8 *>(secret.data()), 32);
  clamp(secret);
  return secret;
}

String publicKey(const String &privateKey) {
  if (privateKey.size() != 32) return String();
  String pub;
  for (int i = 0; i < 32; ++i) pub.push(0);
  crypto_x25519_public_key(reinterpret_cast<u8 *>(pub.data()),
                           reinterpret_cast<const u8 *>(privateKey.data()));
  return pub;
}

String sharedKey(const String &ourPrivate, const String &theirPublic) {
  if (ourPrivate.size() != 32 || theirPublic.size() != 32) return String();
  String shared;
  for (int i = 0; i < 32; ++i) shared.push(0);
  crypto_x25519(reinterpret_cast<u8 *>(shared.data()),
                reinterpret_cast<const u8 *>(ourPrivate.data()),
                reinterpret_cast<const u8 *>(theirPublic.data()));
  return shared;
}

String sharedKey(const Keypair &ourKeypair, const String &theirPublic) {
  return sharedKey(ourKeypair.secretKey, theirPublic);
}

} // namespace X
} // namespace Sec
