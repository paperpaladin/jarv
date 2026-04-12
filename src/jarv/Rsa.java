package jarv;

import java.math.BigInteger;

/**
 * RSA PKCS#1 v1.5 signature verification.
 *
 * The modular exponentiation is BigInteger.modPow and the rest is written
 * out here, because the padding check is the part that goes wrong and
 * calling Signature.verify would have moved the whole question into the
 * library this project exists to not call.
 *
 * What a lax unpad costs: Bleichenbacher's 2006 forgery works against a
 * verifier that finds the DigestInfo after the 0x00 separator and then
 * stops looking. With a public exponent of 3 an attacker can arrange the
 * bytes after the DigestInfo freely, because they are not checked, and a
 * cube root taken over the integers gives a signature that such a
 * verifier accepts without the private key. Three rules close it, and all
 * three are here rather than in a comment: the encoded message must be
 * exactly as long as the modulus, the padding run must be 0xFF to the
 * separator with at least eight of them, and the DigestInfo must end
 * exactly where the encoded message ends.
 *
 * Der.parse enforces the third, because it refuses a window holding
 * anything other than one complete value. That is why the trailing-data
 * case needs no code of its own.
 */
public final class Rsa {
	private Rsa() {
	}

	public static final String OID_RSA = "1.2.840.113549.1.1.1";

	public static final class Key {
		public BigInteger n;
		public BigInteger e;
		/** Modulus length in bytes, which is the encoded message length. */
		public int k;
	}

	/** RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
	public static Key publicKey(X509 c) throws Der.DerError {
		if (!OID_RSA.equals(c.keyAlgOid)) {
			throw new Der.DerError("key algorithm " + c.keyAlgOid
				+ " is not rsaEncryption");
		}
		Der.Node seq = Der.parse(c.keyBits);
		if (!seq.is(Der.UNIVERSAL, Der.SEQUENCE) || seq.kids.size() != 2) {
			throw new Der.DerError("an RSA public key is two integers");
		}
		Key key = new Key();
		key.n = X509.integer(seq.kid(0));
		key.e = X509.integer(seq.kid(1));
		if (key.n.signum() <= 0 || key.e.signum() <= 0) {
			throw new Der.DerError("an RSA public key with a non-positive"
				+ " modulus or exponent");
		}
		key.k = (key.n.bitLength() + 7) / 8;
		return key;
	}

	/**
	 * The encoded message, left-padded to exactly k bytes, or null when
	 * the signature is not a valid representative.
	 *
	 * A signature numerically greater than or equal to the modulus is
	 * refused rather than reduced. Reducing it would make s and s+n two
	 * spellings of one signature.
	 */
	public static byte[] primitive(Key key, byte[] sig) {
		if (sig.length != key.k) {
			return null;
		}
		BigInteger s = new BigInteger(1, sig);
		if (s.compareTo(key.n) >= 0) {
			return null;
		}
		byte[] m = s.modPow(key.e, key.n).toByteArray();
		byte[] em = new byte[key.k];
		if (m.length > key.k) {
			// BigInteger prepends a zero byte when the top bit is set.
			// Anything longer than that is a value that does not fit,
			// which modPow cannot produce.
			if (m.length != key.k + 1 || m[0] != 0) {
				return null;
			}
			System.arraycopy(m, 1, em, 0, key.k);
		} else {
			System.arraycopy(m, 0, em, key.k - m.length, m.length);
		}
		return em;
	}

	/**
	 * The DigestInfo inside an EMSA-PKCS1-v1_5 encoded message, or null.
	 *
	 * EM = 0x00 || 0x01 || PS || 0x00 || T, with PS at least eight 0xFF
	 * bytes and nothing else.
	 */
	public static byte[] unpad(byte[] em) {
		if (em.length < 11 || em[0] != 0x00 || em[1] != 0x01) {
			return null;
		}
		int i = 2;
		while (i < em.length && (em[i] & 0xff) == 0xff) {
			i++;
		}
		if (i - 2 < 8) {
			return null;
		}
		if (i >= em.length || em[i] != 0x00) {
			return null;
		}
		i++;
		if (i >= em.length) {
			return null;
		}
		byte[] t = new byte[em.length - i];
		System.arraycopy(em, i, t, 0, t.length);
		return t;
	}

	/** A DigestInfo: which algorithm, and the digest value. */
	public static final class DigestInfo {
		public String oid;
		public byte[] digest;
	}

	/**
	 * DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier,
	 *                           digest OCTET STRING }
	 *
	 * The parameters field must be absent or NULL. An AlgorithmIdentifier
	 * carrying anything else here is a second place to hide bytes inside
	 * a structure whose length is the only thing stopping a forgery.
	 */
	public static DigestInfo digestInfo(byte[] t) throws Der.DerError {
		Der.Node seq = Der.parse(t);
		if (!seq.is(Der.UNIVERSAL, Der.SEQUENCE) || seq.kids.size() != 2) {
			throw new Der.DerError("a DigestInfo is an algorithm and a digest");
		}
		Der.Node alg = seq.kid(0);
		if (alg.kids.size() > 2) {
			throw new Der.DerError("a digest algorithm identifier with "
				+ alg.kids.size() + " fields");
		}
		if (alg.kids.size() == 2 && !alg.kid(1).is(Der.UNIVERSAL, Der.NULL)) {
			throw new Der.DerError("digest algorithm parameters that are not"
				+ " NULL: " + alg.kid(1));
		}
		if (alg.kids.size() == 2 && alg.kid(1).len != 0) {
			throw new Der.DerError("a NULL with content");
		}
		Der.Node os = seq.kid(1);
		if (!os.is(Der.UNIVERSAL, Der.OCTET_STRING) || os.cons) {
			throw new Der.DerError("the digest in a DigestInfo is "
				+ os + ", not a primitive octet string");
		}
		DigestInfo d = new DigestInfo();
		d.oid = X509.algOid(alg);
		d.digest = os.content();
		return d;
	}

	/** Why a verification failed, or null when it succeeded. */
	public static String verify(Key key, String digestJca, byte[] signed,
			byte[] sig) {
		byte[] em = primitive(key, sig);
		if (em == null) {
			return "the signature is not a valid representative for this key";
		}
		byte[] t = unpad(em);
		if (t == null) {
			return "the encoded message is not PKCS#1 v1.5 padded";
		}
		DigestInfo di;
		try {
			di = digestInfo(t);
		} catch (Der.DerError e) {
			return e.getMessage();
		}
		String named = Digest.jcaForOid(di.oid);
		if (named == null) {
			return "digest algorithm " + di.oid + " is not one this verifier"
				+ " computes";
		}
		if (!named.equals(digestJca)) {
			return "the signature is over a " + named + " digest where the"
				+ " signer says " + digestJca;
		}
		byte[] want = Digest.of(named, signed, 0, signed.length);
		if (want == null) {
			return "no " + named + " available";
		}
		if (want.length != di.digest.length) {
			return "a " + di.digest.length + "-byte digest where " + named
				+ " produces " + want.length;
		}
		int diff = 0;
		for (int i = 0; i < want.length; i++) {
			diff |= want[i] ^ di.digest[i];
		}
		if (diff != 0) {
			return "the signed digest is " + Hex.of(di.digest) + " and the"
				+ " content digests to " + Hex.of(want);
		}
		return null;
	}
}
