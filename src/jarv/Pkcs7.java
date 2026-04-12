package jarv;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * The PKCS#7 SignedData in a .RSA, .DSA or .EC block.
 *
 * The content is detached: the SignedData's own contentInfo carries no
 * data, and what the signature is over is the .SF file sitting beside the
 * block in the archive. That indirection is the whole shape of JAR
 * signing and it is why a signature can be valid while covering nothing
 * anyone cares about.
 */
public final class Pkcs7 {
	public static final String OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
	public static final String OID_DATA = "1.2.840.113549.1.7.1";
	public static final String OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
	public static final String OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
	public static final String OID_SIGNING_TIME = "1.2.840.113549.1.9.5";
	public static final String OID_TIMESTAMP_TOKEN =
		"1.2.840.113549.1.9.16.2.14";

	public int version;
	public final List<String> digestAlgorithms = new ArrayList<String>();
	public String contentType;
	/** Present only when the content is not detached. */
	public byte[] content;
	public final List<X509> certs = new ArrayList<X509>();
	public final List<Signer> signers = new ArrayList<Signer>();
	public boolean hasCrls;

	public static final class Attr {
		public String oid;
		public Der.Node values;
	}

	public static final class Signer {
		public int version;
		public byte[] issuerDer;
		public String issuer;
		public BigInteger serial;
		public String digestOid;
		public String encryptionOid;
		public Der.Node encryptionParams;
		public byte[] signature;
		/** The authenticated attributes, as the SET they must be signed as. */
		public Der.Node authAttrs;
		public final List<Attr> auth = new ArrayList<Attr>();
		public final List<Attr> unauth = new ArrayList<Attr>();
		public boolean hasTimestamp;

		public Attr findAuth(String oid) {
			for (Attr a : auth) {
				if (a.oid.equals(oid)) {
					return a;
				}
			}
			return null;
		}
	}

	public Pkcs7(byte[] der) throws Der.DerError {
		Der.Node root = Der.parse(der);
		if (root.kids.isEmpty()) {
			throw new Der.DerError("an empty ContentInfo");
		}
		String outer = Der.oid(root.kid(0));
		if (!OID_SIGNED_DATA.equals(outer)) {
			throw new Der.DerError("content type " + outer + ", not signedData");
		}
		if (root.kids.size() < 2 || !root.kid(1).is(Der.CONTEXT, 0)
				|| root.kid(1).kids.isEmpty()) {
			throw new Der.DerError("signedData with no content");
		}
		Der.Node sd = root.kid(1).kid(0);
		int i = 0;
		version = (int) X509.integer(sd.kid(i++)).longValue();
		for (Der.Node alg : sd.kid(i++).kids) {
			digestAlgorithms.add(X509.algOid(alg));
		}
		Der.Node ci = sd.kid(i++);
		contentType = ci.kids.isEmpty() ? null : Der.oid(ci.kid(0));
		if (ci.kids.size() > 1 && ci.kid(1).is(Der.CONTEXT, 0)
				&& !ci.kid(1).kids.isEmpty()) {
			content = ci.kid(1).kid(0).content();
		}
		while (i < sd.kids.size() && sd.kid(i).tagClass == Der.CONTEXT) {
			Der.Node n = sd.kid(i++);
			if (n.tag == 0) {
				for (Der.Node c : n.kids) {
					// An ExtendedCertificate or an attribute certificate is
					// context-tagged here. Neither is an X.509 certificate
					// and neither is followed.
					if (c.is(Der.UNIVERSAL, Der.SEQUENCE)) {
						certs.add(new X509(c));
					}
				}
			} else if (n.tag == 1) {
				hasCrls = n.len > 0;
			}
		}
		if (i >= sd.kids.size()) {
			throw new Der.DerError("signedData with no signerInfos");
		}
		for (Der.Node si : sd.kid(i).kids) {
			signers.add(signer(si));
		}
	}

	private static Signer signer(Der.Node si) throws Der.DerError {
		Signer s = new Signer();
		int i = 0;
		s.version = (int) X509.integer(si.kid(i++)).longValue();
		Der.Node sid = si.kid(i++);
		if (sid.is(Der.CONTEXT, 0)) {
			throw new Der.DerError("a signer identified by subject key"
				+ " identifier, which this verifier does not resolve");
		}
		s.issuerDer = sid.kid(0).encoded();
		s.issuer = X509.name(sid.kid(0));
		s.serial = X509.integer(sid.kid(1));
		s.digestOid = X509.algOid(si.kid(i++));
		if (si.kid(i).is(Der.CONTEXT, 0)) {
			s.authAttrs = si.kid(i++);
			readAttrs(s.authAttrs, s.auth);
		}
		Der.Node enc = si.kid(i++);
		s.encryptionOid = X509.algOid(enc);
		s.encryptionParams = enc.kids.size() > 1 ? enc.kid(1) : null;
		Der.Node sig = si.kid(i++);
		if (!sig.is(Der.UNIVERSAL, Der.OCTET_STRING)) {
			throw new Der.DerError("the encrypted digest is " + sig
				+ ", not an octet string");
		}
		s.signature = sig.content();
		if (i < si.kids.size() && si.kid(i).is(Der.CONTEXT, 1)) {
			readAttrs(si.kid(i), s.unauth);
			for (Attr a : s.unauth) {
				if (OID_TIMESTAMP_TOKEN.equals(a.oid)) {
					s.hasTimestamp = true;
				}
			}
		}
		return s;
	}

	private static void readAttrs(Der.Node set, List<Attr> out)
			throws Der.DerError {
		for (Der.Node a : set.kids) {
			if (a.kids.size() < 2) {
				throw new Der.DerError("an attribute with no value");
			}
			Attr at = new Attr();
			at.oid = Der.oid(a.kid(0));
			at.values = a.kid(1);
			out.add(at);
		}
	}

	/**
	 * The certificate a SignerInfo points at, or null.
	 *
	 * Matched on the raw DER of the issuer name and on the serial, not on
	 * the printed name. Two names that print alike can encode differently,
	 * and a match made on the printed form joins a signer to a
	 * certificate nobody issued it.
	 */
	public X509 certFor(Signer s) {
		for (X509 c : certs) {
			if (c.serial.equals(s.serial)
					&& java.util.Arrays.equals(c.issuerDer, s.issuerDer)) {
				return c;
			}
		}
		return null;
	}

	/**
	 * The bytes a signature over authenticated attributes covers.
	 *
	 * PKCS#7 says the attributes are signed as a SET OF, DER-encoded,
	 * while in the SignerInfo they appear with an implicit [0] tag. So the
	 * leading identifier octet is replaced by 0x31 and nothing else
	 * changes. Signing the bytes as they appear in the file instead gives
	 * a signature that will not verify anywhere, and verifying them that
	 * way accepts a signature nobody else will.
	 */
	public static byte[] authAttrBytes(Signer s) {
		byte[] b = s.authAttrs.encoded();
		b[0] = 0x31;
		return b;
	}
}
