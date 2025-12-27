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
