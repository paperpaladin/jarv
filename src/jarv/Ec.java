package jarv;

import java.math.BigInteger;

/**
 * ECDSA verification over the NIST prime curves.
 *
 * Affine arithmetic with a modular inverse per point operation. That is
 * the slow way and it is the right trade here: a jar has a handful of
 * signatures, the whole suite spends under a second in this file, and
 * Jacobian coordinates would add a page of code whose bugs produce wrong
 * answers rather than slow ones.
 *
 * shortcut: affine point arithmetic, one modInverse per add and double.
 * Move to Jacobian coordinates if verification ever shows up in a profile.
 *
 * Four checks decide whether this is verification or decoration:
 * r and s must both be in [1, n-1], the public point must be on the
 * curve, the digest is truncated to the bit length of n and not to its
 * byte length, and the comparison is r == x1 mod n rather than r == x1.
 */
public final class Ec {
	private Ec() {
	}

	public static final String OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";

	public static final class Curve {
		public final String oid;
		public final String name;
		public final BigInteger p;
		public final BigInteger a;
		public final BigInteger b;
		public final BigInteger gx;
		public final BigInteger gy;
		public final BigInteger n;

		Curve(String oid, String name, String p, String a, String b, String gx,
				String gy, String n) {
			this.oid = oid;
			this.name = name;
			this.p = new BigInteger(p, 16);
			this.a = new BigInteger(a, 16);
			this.b = new BigInteger(b, 16);
			this.gx = new BigInteger(gx, 16);
			this.gy = new BigInteger(gy, 16);
			this.n = new BigInteger(n, 16);
		}
	}

	private static final Curve[] CURVES = {
		new Curve("1.2.840.10045.3.1.7", "P-256",
			"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
			"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
			"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
			"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
			"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
			"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
		new Curve("1.3.132.0.34", "P-384",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
				+ "ffffffff0000000000000000ffffffff",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
				+ "ffffffff0000000000000000fffffffc",
			"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
				+ "c656398d8a2ed19d2a85c8edd3ec2aef",
			"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
				+ "5502f25dbf55296c3a545e3872760ab7",
			"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
				+ "0a60b1ce1d7e819d7a431d7c90ea0e5f",
			"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
				+ "581a0db248b0a77aecec196accc52973"),
		new Curve("1.3.132.0.35", "P-521",
			"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				+ "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				+ "ffffffff",
			"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				+ "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				+ "fffffffc",
			"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
				+ "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd4"
				+ "6b503f00",
			"00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"
				+ "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31"
				+ "c2e5bd66",
			"011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
				+ "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be9476"
				+ "9fd16650",
			"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				+ "fffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709"
				+ "a5d03bb5c9b8899c47aebb6fb71e91386409"),
	};

	public static Curve curve(String oid) {
		for (Curve c : CURVES) {
			if (c.oid.equals(oid)) {
				return c;
			}
		}
		return null;
	}

	/** A point, with null standing for the point at infinity. */
	static final class Pt {
		final BigInteger x;
		final BigInteger y;

		Pt(BigInteger x, BigInteger y) {
			this.x = x;
			this.y = y;
		}
	}

	static boolean onCurve(Curve c, Pt q) {
		if (q == null) {
			return false;
		}
		if (q.x.signum() < 0 || q.x.compareTo(c.p) >= 0
				|| q.y.signum() < 0 || q.y.compareTo(c.p) >= 0) {
			return false;
		}
		BigInteger lhs = q.y.multiply(q.y).mod(c.p);
		BigInteger rhs = q.x.multiply(q.x).add(c.a).multiply(q.x).add(c.b)
			.mod(c.p);
		return lhs.equals(rhs);
	}

	static Pt dbl(Curve c, Pt q) {
		if (q == null || q.y.signum() == 0) {
			return null;
		}
		BigInteger num = q.x.multiply(q.x).multiply(BigInteger.valueOf(3))
			.add(c.a);
		BigInteger den = q.y.add(q.y).modInverse(c.p);
		BigInteger l = num.multiply(den).mod(c.p);
		BigInteger x = l.multiply(l).subtract(q.x).subtract(q.x).mod(c.p);
		BigInteger y = l.multiply(q.x.subtract(x)).subtract(q.y).mod(c.p);
		return new Pt(x, y);
	}

	static Pt add(Curve c, Pt s, Pt t) {
		if (s == null) {
			return t;
		}
		if (t == null) {
			return s;
		}
		if (s.x.equals(t.x)) {
			return s.y.equals(t.y) ? dbl(c, s) : null;
		}
		BigInteger l = t.y.subtract(s.y)
			.multiply(t.x.subtract(s.x).mod(c.p).modInverse(c.p)).mod(c.p);
		BigInteger x = l.multiply(l).subtract(s.x).subtract(t.x).mod(c.p);
		BigInteger y = l.multiply(s.x.subtract(x)).subtract(s.y).mod(c.p);
		return new Pt(x, y);
	}

	static Pt mul(Curve c, BigInteger k, Pt q) {
		Pt r = null;
		for (int i = k.bitLength() - 1; i >= 0; i--) {
			r = dbl(c, r);
			if (k.testBit(i)) {
				r = add(c, r, q);
			}
		}
		return r;
	}

	/**
	 * The public point from a SubjectPublicKeyInfo.
	 *
	 * Only the uncompressed form, 0x04 followed by two field elements of
	 * exactly the field length. A compressed point would have to be
	 * decompressed, which is a square root in the field and a sign
	 * choice, and nothing the JDK emits uses one. Refused, not guessed.
	 */
	public static Pt publicPoint(Curve c, byte[] bits) throws Der.DerError {
		int flen = (c.p.bitLength() + 7) / 8;
		if (bits.length != 1 + 2 * flen) {
			throw new Der.DerError("an EC point of " + bits.length
				+ " bytes where " + c.name + " uncompressed is "
				+ (1 + 2 * flen));
		}
		if (bits[0] != 0x04) {
			throw new Der.DerError("an EC point in form 0x"
				+ Integer.toHexString(bits[0] & 0xff) + ", and only the"
				+ " uncompressed form 0x04 is read here");
		}
		byte[] xb = new byte[flen];
		byte[] yb = new byte[flen];
		System.arraycopy(bits, 1, xb, 0, flen);
		System.arraycopy(bits, 1 + flen, yb, 0, flen);
		Pt q = new Pt(new BigInteger(1, xb), new BigInteger(1, yb));
		if (!onCurve(c, q)) {
			throw new Der.DerError("the public point is not on " + c.name);
		}
		return q;
	}

	public static Curve curveOf(X509 c) throws Der.DerError {
		if (!OID_EC_PUBLIC_KEY.equals(c.keyAlgOid)) {
			throw new Der.DerError("key algorithm " + c.keyAlgOid
				+ " is not id-ecPublicKey");
		}
		if (c.keyAlgParams == null) {
			throw new Der.DerError("an EC key with no curve named");
		}
		String oid = Der.oid(c.keyAlgParams);
		if (oid == null) {
			throw new Der.DerError("EC parameters that are not a named curve");
		}
		Curve cv = curve(oid);
		if (cv == null) {
			throw new Der.DerError("curve " + oid + " is not one of the three"
				+ " NIST prime curves this verifier knows");
		}
		return cv;
	}

	/**
	 * The integer a digest stands for.
	 *
	 * Truncation is by BIT length of the group order, not by byte length.
	 * The two agree for P-256 and P-384 and differ for P-521, where n is
	 * 521 bits: a verifier that truncates to 66 bytes keeps seven bits
	 * too many for a SHA-512 digest and rejects valid signatures.
	 */
	static BigInteger e(Curve c, byte[] digest) {
		BigInteger z = new BigInteger(1, digest);
		int excess = digest.length * 8 - c.n.bitLength();
		return excess > 0 ? z.shiftRight(excess) : z;
	}

	/** Why the signature failed, or null when it verified. */
	public static String verify(Curve c, Pt q, String digestJca, byte[] signed,
			byte[] sig) {
		BigInteger r;
		BigInteger s;
		try {
			Der.Node seq = Der.parse(sig);
			if (!seq.is(Der.UNIVERSAL, Der.SEQUENCE) || seq.kids.size() != 2) {
				return "an ECDSA signature is two integers in a sequence";
			}
			r = X509.integer(seq.kid(0));
			s = X509.integer(seq.kid(1));
		} catch (Der.DerError err) {
			return err.getMessage();
		}
		if (r.signum() <= 0 || r.compareTo(c.n) >= 0
				|| s.signum() <= 0 || s.compareTo(c.n) >= 0) {
			return "r or s is outside [1, n-1]";
		}
		byte[] d = Digest.of(digestJca, signed, 0, signed.length);
		if (d == null) {
			return "no " + digestJca + " available";
		}
		BigInteger w = s.modInverse(c.n);
		BigInteger u1 = e(c, d).multiply(w).mod(c.n);
		BigInteger u2 = r.multiply(w).mod(c.n);
		Pt g = new Pt(c.gx, c.gy);
		Pt p = add(c, mul(c, u1, g), mul(c, u2, q));
		if (p == null) {
			return "u1*G + u2*Q is the point at infinity";
		}
		if (!p.x.mod(c.n).equals(r)) {
			return "r is " + r.toString(16) + " and x1 mod n is "
				+ p.x.mod(c.n).toString(16);
		}
		return null;
	}
}
