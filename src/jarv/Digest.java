package jarv;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Digest names, and the one place MessageDigest is called.
 *
 * SHA-2 is not written here. The collection already has an implementation
 * and the README says which calls jarv makes into the platform. What is
 * written here is the name mapping, which is a real source of
 * disagreement: the JAR spec's older attribute is SHA1-Digest with no
 * hyphen, the newer ones are SHA-256-Digest with one, and a verifier that
 * recognises only the spelling it was written against silently treats a
 * section as having no digest at all, which reads as "unsigned".
 */
public final class Digest {
	private Digest() {
	}

	/** JCA name for a manifest digest attribute prefix, or null. */
	public static String jcaName(String prefix) {
		String p = prefix.toUpperCase(java.util.Locale.ROOT);
		if (p.equals("SHA") || p.equals("SHA1") || p.equals("SHA-1")) {
			return "SHA-1";
		}
		if (p.equals("MD5")) {
			return "MD5";
		}
		if (p.equals("MD2")) {
			return "MD2";
		}
		if (p.equals("SHA-224") || p.equals("SHA224")) {
			return "SHA-224";
		}
		if (p.equals("SHA-256") || p.equals("SHA256")) {
			return "SHA-256";
		}
		if (p.equals("SHA-384") || p.equals("SHA384")) {
			return "SHA-384";
		}
		if (p.equals("SHA-512") || p.equals("SHA-512/224")
				|| p.equals("SHA-512/256") || p.equals("SHA512")) {
			return p.startsWith("SHA-512/") ? p : "SHA-512";
		}
		if (p.startsWith("SHA3-")) {
			return p;
		}
		return null;
	}

	// OID, JCA name. Both directions are read from this one table so the
	// two cannot drift apart.
	private static final String[][] OIDS = {
		{"1.3.14.3.2.26", "SHA-1"},
		{"1.2.840.113549.2.5", "MD5"},
		{"1.2.840.113549.2.2", "MD2"},
		{"2.16.840.1.101.3.4.2.4", "SHA-224"},
		{"2.16.840.1.101.3.4.2.1", "SHA-256"},
		{"2.16.840.1.101.3.4.2.2", "SHA-384"},
		{"2.16.840.1.101.3.4.2.3", "SHA-512"},
		{"2.16.840.1.101.3.4.2.7", "SHA3-224"},
		{"2.16.840.1.101.3.4.2.8", "SHA3-256"},
		{"2.16.840.1.101.3.4.2.9", "SHA3-384"},
		{"2.16.840.1.101.3.4.2.10", "SHA3-512"},
	};

	/** JCA name for a digest algorithm OID, or null. */
	public static String jcaForOid(String oid) {
		for (String[] row : OIDS) {
			if (row[0].equals(oid)) {
				return row[1];
			}
		}
		return null;
	}

	/** Digest algorithm OID for a JCA name, or null. */
	public static String oidForJca(String jca) {
		for (String[] row : OIDS) {
			if (row[1].equals(jca)) {
				return row[0];
			}
		}
		return null;
	}

	// A signature algorithm OID names a digest and a key type together.
	// The bare rsaEncryption OID names neither, and the JDK uses it in
	// SignerInfo.digestEncryptionAlgorithm, which is why the digest is
	// taken from SignerInfo.digestAlgorithm and this table is only a
	// cross-check on the ones that do say.
	private static final String[][] SIGALGS = {
		{"1.2.840.113549.1.1.1", "RSA", null},
		{"1.2.840.113549.1.1.4", "RSA", "MD5"},
		{"1.2.840.113549.1.1.5", "RSA", "SHA-1"},
		{"1.2.840.113549.1.1.14", "RSA", "SHA-224"},
		{"1.2.840.113549.1.1.11", "RSA", "SHA-256"},
		{"1.2.840.113549.1.1.12", "RSA", "SHA-384"},
		{"1.2.840.113549.1.1.13", "RSA", "SHA-512"},
		{"1.2.840.10045.2.1", "EC", null},
		{"1.2.840.10045.4.1", "EC", "SHA-1"},
		{"1.2.840.10045.4.3.1", "EC", "SHA-224"},
		{"1.2.840.10045.4.3.2", "EC", "SHA-256"},
		{"1.2.840.10045.4.3.3", "EC", "SHA-384"},
		{"1.2.840.10045.4.3.4", "EC", "SHA-512"},
		{"1.2.840.10040.4.1", "DSA", null},
		{"1.2.840.10040.4.3", "DSA", "SHA-1"},
		{"2.16.840.1.101.3.4.3.2", "DSA", "SHA-256"},
	};

	/** RSA, EC, DSA, or null for an OID that is none of them. */
	public static String keyTypeForSigAlg(String oid) {
		for (String[] row : SIGALGS) {
			if (row[0].equals(oid)) {
				return row[1];
			}
		}
		return null;
	}

	/** The digest a signature algorithm OID implies, or null if it says none. */
	public static String digestForSigAlg(String oid) {
		for (String[] row : SIGALGS) {
			if (row[0].equals(oid)) {
				return row[2];
			}
		}
		return null;
	}

	public static byte[] of(String jca, byte[] data, int off, int len) {
		MessageDigest md = get(jca);
		if (md == null) {
			return null;
		}
		md.update(data, off, len);
		return md.digest();
	}

	public static MessageDigest get(String jca) {
		try {
			return MessageDigest.getInstance(jca);
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}
}
