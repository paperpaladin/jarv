package jarv;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * As much of X.509 as a JAR signature needs: who signed, with what key,
 * when the certificate was valid, and who signed the certificate.
 *
 * Names are kept twice. The printable form is for the oracle comparison
 * and for people; the raw DER of the Name is what chain building compares,
 * because two names that print the same can encode differently (a
 * PrintableString and a UTF8String of the same text) and an issuer match
 * done on the printed form would join two unrelated chains.
 */
public final class X509 {
	public final Der.Node cert;
	public final Der.Node tbs;
	public int version = 1;
	public BigInteger serial;
	public String sigAlgOid;
	public Der.Node sigAlgParams;
	public byte[] signature;
	public byte[] issuerDer;
	public byte[] subjectDer;
	public String issuer;
	public String subject;
	public long notBefore;
	public long notAfter;
	public String notBeforeText;
	public String notAfterText;
	public String keyAlgOid;
	public Der.Node keyAlgParams;
	public byte[] keyBits;
	public boolean isCa;
	public boolean hasBasicConstraints;
	public final List<String> extensions = new ArrayList<String>();

	public X509(Der.Node cert) throws Der.DerError {
		this.cert = cert;
		if (!cert.is(Der.UNIVERSAL, Der.SEQUENCE) || cert.kids.size() != 3) {
			throw new Der.DerError("a certificate is three fields in a"
				+ " sequence, this has " + cert.kids.size());
		}
		tbs = cert.kid(0);
		Der.Node algId = cert.kid(1);
		sigAlgOid = algOid(algId);
		sigAlgParams = algId.kids.size() > 1 ? algId.kid(1) : null;
		signature = bitString(cert.kid(2));

		int i = 0;
		if (!tbs.kids.isEmpty() && tbs.kid(0).is(Der.CONTEXT, 0)) {
			Der.Node v = tbs.kid(0);
			if (v.kids.isEmpty()) {
				throw new Der.DerError("empty version field");
			}
			version = (int) integer(v.kid(0)).longValue() + 1;
			i = 1;
		}
		serial = integer(tbs.kid(i++));
		Der.Node inner = tbs.kid(i++);
		String innerOid = algOid(inner);
		if (!innerOid.equals(sigAlgOid)) {
			// RFC 5280 requires the two to match. They are signed and
			// unsigned copies of the same field, so a difference is an
			// attempt to have a verifier and a displayer disagree.
			throw new Der.DerError("tbsCertificate says " + innerOid
				+ " and the outer signature says " + sigAlgOid);
		}
		Der.Node iss = tbs.kid(i++);
		issuerDer = iss.encoded();
		issuer = name(iss);
		Der.Node val = tbs.kid(i++);
		notBefore = time(val.kid(0));
		notAfter = time(val.kid(1));
		notBeforeText = timeText(notBefore);
		notAfterText = timeText(notAfter);
		Der.Node sub = tbs.kid(i++);
		subjectDer = sub.encoded();
		subject = name(sub);
		Der.Node spki = tbs.kid(i++);
		keyAlgOid = algOid(spki.kid(0));
		keyAlgParams = spki.kid(0).kids.size() > 1 ? spki.kid(0).kid(1) : null;
		keyBits = bitString(spki.kid(1));
		for (; i < tbs.kids.size(); i++) {
			Der.Node n = tbs.kid(i);
			if (n.is(Der.CONTEXT, 3)) {
				readExtensions(n);
			}
		}
	}

	private void readExtensions(Der.Node holder) throws Der.DerError {
		if (holder.kids.isEmpty()) {
			return;
		}
		for (Der.Node ext : holder.kid(0).kids) {
			if (ext.kids.isEmpty()) {
				continue;
			}
			String oid = Der.oid(ext.kid(0));
			boolean critical = false;
			int vi = 1;
			if (ext.kids.size() > 2) {
				critical = ext.kid(1).len == 1
					&& (ext.kid(1).buf[ext.kid(1).contentOff()] & 0xff) != 0;
				vi = 2;
			}
			extensions.add(oid + (critical ? " critical" : ""));
			if ("2.5.29.19".equals(oid)) {
				hasBasicConstraints = true;
				Der.Node v = Der.parse(ext.kid(vi).content());
				if (!v.kids.isEmpty() && v.kid(0).is(Der.UNIVERSAL, Der.BOOLEAN)) {
					isCa = (v.kid(0).buf[v.kid(0).contentOff()] & 0xff) != 0;
				}
			}
		}
	}

	static String algOid(Der.Node alg) throws Der.DerError {
		if (alg.kids.isEmpty()) {
			throw new Der.DerError("an algorithm identifier with no oid");
		}
		String oid = Der.oid(alg.kid(0));
		if (oid == null) {
			throw new Der.DerError("an algorithm identifier whose first field"
				+ " is not an object identifier");
		}
		return oid;
	}

	static BigInteger integer(Der.Node n) throws Der.DerError {
		if (!n.is(Der.UNIVERSAL, Der.INTEGER) || n.cons || n.len == 0) {
			throw new Der.DerError("expected an integer, got " + n);
		}
		return new BigInteger(n.content());
	}

	/** Contents of a BIT STRING, refusing any unused bits. */
	static byte[] bitString(Der.Node n) throws Der.DerError {
		if (!n.is(Der.UNIVERSAL, Der.BIT_STRING) || n.cons || n.len < 1) {
			throw new Der.DerError("expected a bit string, got " + n);
		}
		int unused = n.buf[n.contentOff()] & 0xff;
		if (unused != 0) {
			throw new Der.DerError(unused + " unused bits in a bit string that"
				+ " should hold whole bytes");
		}
		byte[] out = new byte[n.len - 1];
		System.arraycopy(n.buf, n.contentOff() + 1, out, 0, out.length);
		return out;
	}

	private static final String[][] DN = {
		{"2.5.4.3", "CN"}, {"2.5.4.4", "SN"}, {"2.5.4.5", "serialNumber"},
		{"2.5.4.6", "C"}, {"2.5.4.7", "L"}, {"2.5.4.8", "ST"},
		{"2.5.4.9", "street"}, {"2.5.4.10", "O"}, {"2.5.4.11", "OU"},
		{"2.5.4.12", "title"}, {"2.5.4.42", "GN"}, {"2.5.4.43", "initials"},
		{"2.5.4.46", "dnQualifier"}, {"2.5.4.65", "pseudonym"},
		{"0.9.2342.19200300.100.1.1", "UID"},
		{"0.9.2342.19200300.100.1.25", "DC"},
		{"1.2.840.113549.1.9.1", "emailAddress"},
	};

	/**
	 * A Name, printed the way openssl prints one: encoding order, short
	 * names where it has them, joined with ", ". Matching the oracle's
	 * format exactly is what lets the comparison be on the whole string
	 * rather than on a normalisation nobody checks.
	 */
	static String name(Der.Node n) {
		StringBuilder sb = new StringBuilder();
		for (Der.Node rdn : n.kids) {
			for (Der.Node atv : rdn.kids) {
				if (atv.kids.size() < 2) {
					continue;
				}
				String oid = Der.oid(atv.kids.get(0));
				String label = oid;
				for (String[] row : DN) {
					if (row[0].equals(oid)) {
						label = row[1];
						break;
					}
				}
				if (sb.length() > 0) {
					sb.append(", ");
				}
				sb.append(label).append('=').append(text(atv.kids.get(1)));
			}
		}
		return sb.toString();
	}

	static String text(Der.Node n) {
		if (n.tag == Der.BMP_STRING) {
			return new String(n.content(), StandardCharsets.UTF_16BE);
		}
		if (n.tag == Der.UTF8_STRING) {
			return new String(n.content(), StandardCharsets.UTF_8);
		}
		return new String(n.content(), StandardCharsets.ISO_8859_1);
	}

	/** Seconds since the epoch, from UTCTime or GeneralizedTime. */
	static long time(Der.Node n) throws Der.DerError {
		String s = new String(n.content(), StandardCharsets.US_ASCII);
		int year;
		int off;
		if (n.is(Der.UNIVERSAL, Der.UTC_TIME)) {
			if (s.length() != 13 || s.charAt(12) != 'Z') {
				throw new Der.DerError("UTCTime " + s + " is not YYMMDDHHMMSSZ,"
					+ " which is the only form DER allows");
			}
			int yy = num(s, 0, 2);
			year = yy >= 50 ? 1900 + yy : 2000 + yy;
			off = 2;
		} else if (n.is(Der.UNIVERSAL, Der.GENERALIZED_TIME)) {
			if (s.length() != 15 || s.charAt(14) != 'Z') {
				throw new Der.DerError("GeneralizedTime " + s + " is not"
					+ " YYYYMMDDHHMMSSZ");
			}
			year = num(s, 0, 4);
			off = 4;
		} else {
			throw new Der.DerError("expected a time, got " + n);
		}
		int mon = num(s, off, 2);
		int day = num(s, off + 2, 2);
		int hh = num(s, off + 4, 2);
		int mm = num(s, off + 6, 2);
		int ss = num(s, off + 8, 2);
		if (mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59
				|| ss > 60) {
			throw new Der.DerError("time " + s + " is out of range");
		}
		return epoch(year, mon, day) * 86400L + hh * 3600L + mm * 60L + ss;
	}

	private static int num(String s, int i, int n) throws Der.DerError {
		int v = 0;
		for (int k = 0; k < n; k++) {
			char c = s.charAt(i + k);
			if (c < '0' || c > '9') {
				throw new Der.DerError("non-digit in a time field");
			}
			v = v * 10 + (c - '0');
		}
		return v;
	}

	/** Days from 1970-01-01 to the given date, by the civil-days formula. */
	static long epoch(int y, int m, int d) {
		long yy = y;
		yy -= m <= 2 ? 1 : 0;
		long era = (yy >= 0 ? yy : yy - 399) / 400;
		long yoe = yy - era * 400;
		long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
		long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
		return era * 146097 + doe - 719468;
	}

	private static final String[] MON = {"Jan", "Feb", "Mar", "Apr", "May",
		"Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

	/** openssl's own format, so the comparison needs no normalisation. */
	static String timeText(long t) {
		long days = Math.floorDiv(t, 86400L);
		long sec = Math.floorMod(t, 86400L);
		long z = days + 719468;
		long era = (z >= 0 ? z : z - 146096) / 146097;
		long doe = z - era * 146097;
		long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
		long y = yoe + era * 400;
		long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
		long mp = (5 * doy + 2) / 153;
		long d = doy - (153 * mp + 2) / 5 + 1;
		long m = mp + (mp < 10 ? 3 : -9);
		y += m <= 2 ? 1 : 0;
		return String.format("%s %2d %02d:%02d:%02d %d GMT", MON[(int) m - 1],
			d, sec / 3600, (sec / 60) % 60, sec % 60, y);
	}
}
