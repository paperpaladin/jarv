package jarv;

import java.util.ArrayList;
import java.util.List;

/**
 * The verdict: which signers cover which entries, and what is left over.
 *
 * The chain of claims a JAR signature makes, in the order it has to be
 * walked, because a verifier that checks them out of order can say yes
 * to a file whose contents nobody signed:
 *
 *   The signature block signs the .SF file. Nothing else.
 *   The .SF ties itself to the manifest, either with one digest over
 *   the whole manifest file or with a digest per section.
 *   The manifest ties itself to each entry with a digest of the entry's
 *   uncompressed bytes.
 *
 * An entry with no manifest section is attached to none of that. It
 * sits in the archive, it is extracted like any other member, and no
 * signature says anything about it. That is the case this program
 * exists to make loud.
 */
public final class Verify {
	public final Jar jar;
	public final List<Signer> signers = new ArrayList<Signer>();
	public final List<EntryState> entries = new ArrayList<EntryState>();
	public final List<String> problems = new ArrayList<String>();
	/** Signable entries with no manifest section at all. */
	public int unsigned;
	/** In the manifest, digest intact, and no usable signer covers them. */
	public int uncovered;
	/** In the manifest and digesting to something else. */
	public int mismatched;
	/** Covered by some signers and not others. */
	public int partial;
	/** Signable entries covered by every usable signer. */
	public int fullyCovered;

	public static final class Signer {
		public String sfName;
		public String blockName;
		public String subject = "-";
		public X509 cert;
		public List<X509> chain = new ArrayList<X509>();
		/** "ok", "bad ...", or "refused ...". */
		public String sigStatus = "refused nothing read";
		/** "manifest", "sections", or "bad ...". */
		public String linkStatus = "none";
		public boolean wholeManifest;
		public String digestAlg = "-";
		public boolean selfSigned;
		public boolean expired;
		public boolean notYetValid;
		public boolean timestamped;
		/** Manifest section names this signer authenticates. */
		public final List<String> authenticated = new ArrayList<String>();

		public boolean usable() {
			return sigStatus.equals("ok") && !linkStatus.startsWith("bad")
				&& !linkStatus.equals("none");
		}
	}

	public static final class EntryState {
		public Entry entry;
		public boolean signable;
		public boolean inManifest;
		/** "ok", "mismatch", "nodigest", "unreadable", or "-". */
		public String digest = "-";
		public final List<String> by = new ArrayList<String>();
	}

	public Verify(Jar jar, long now) {
		this.jar = jar;
		problems.addAll(jar.problems);
		for (Jar.Sig s : jar.sigs) {
			signers.add(signer(s, now));
		}
		for (Entry e : jar.zip.entries()) {
			entries.add(entryState(e));
		}
		if (jar.manifest != null) {
			for (Manifest.Section ms : jar.manifest.sections) {
				if (ms.name != null && !present(ms.name)) {
					problems.add("the manifest digests " + ms.name
						+ ", which is not in the archive");
				}
			}
		}
		// The four ways a signable entry can fail to be covered are
		// counted apart, because they are four different statements.
		// An entry absent from the manifest is the one this program is
		// about; an entry whose digest does not match is a tampered
		// archive; an entry in the manifest that no working signer
		// vouches for is a third thing again.
		for (EntryState st : entries) {
			if (!st.signable) {
				continue;
			}
			if (st.digest.equals("mismatch") || st.digest.equals("unreadable")
					|| st.digest.equals("weak")) {
				mismatched++;
			} else if (!st.inManifest) {
				unsigned++;
			} else if (st.by.isEmpty()) {
				uncovered++;
			} else if (st.by.size() < usableSigners()) {
				partial++;
			} else {
				fullyCovered++;
			}
		}
	}

	private boolean present(String name) {
		for (Entry e : jar.zip.entries()) {
			if (e.name.equals(name)) {
				return true;
			}
		}
		return false;
	}

	public int usableSigners() {
		int n = 0;
		for (Signer s : signers) {
			if (s.usable()) {
				n++;
			}
		}
		return n;
	}

	private Signer signer(Jar.Sig s, long now) {
		Signer out = new Signer();
		out.sfName = s.sfName;
		out.blockName = s.blockName;
		if (s.blockBytes == null) {
			out.sigStatus = "refused no signature block";
			return out;
		}
		if (s.sfBytes == null) {
			out.sigStatus = "refused the signature file could not be read";
			return out;
		}
		Pkcs7 p7;
		try {
			p7 = new Pkcs7(s.blockBytes);
		} catch (Der.DerError e) {
			out.sigStatus = "refused " + e.getMessage();
			return out;
		}
		if (p7.signers.size() != 1) {
			// A JAR signature block holds one SignerInfo. Several would
			// mean several signers behind one .SF, which no JDK produces
			// and which would make the coverage table ambiguous.
			out.sigStatus = "refused " + p7.signers.size()
				+ " signerInfos in one block";
			return out;
		}
		Pkcs7.Signer si = p7.signers.get(0);
		out.timestamped = si.hasTimestamp;
		out.cert = p7.certFor(si);
		if (out.cert == null) {
			out.sigStatus = "refused no certificate in the block matches the"
				+ " signer";
			return out;
		}
		out.subject = out.cert.subject;
		out.chain = X509.chain(p7.certs, out.cert);
		out.selfSigned = java.util.Arrays.equals(out.cert.issuerDer,
			out.cert.subjectDer);
		out.expired = now > out.cert.notAfter;
		out.notYetValid = now < out.cert.notBefore;
		out.digestAlg = Digest.jcaForOid(si.digestOid);
		if (out.digestAlg == null) {
			out.sigStatus = "refused digest algorithm " + si.digestOid;
			return out;
		}
		out.sigStatus = Pkcs7.checkAttrs(p7, si, s.sfBytes,
			out.digestAlg);
		if (out.sigStatus == null) {
			byte[] signed = si.authAttrs == null ? s.sfBytes
				: Pkcs7.authAttrBytes(si);
			out.sigStatus = signature(out.cert, si, out.digestAlg, signed);
		}
		if (out.sigStatus == null) {
			out.sigStatus = "ok";
		}
		link(out, s);
		return out;
	}

	/** Verify the block's signature over the signature file. */
	private static String signature(X509 cert, Pkcs7.Signer si, String digest,
			byte[] signed) {
		String kind = Digest.keyTypeForSigAlg(si.encryptionOid);
		try {
			if ("RSA".equals(kind)) {
				String why = Rsa.verify(Rsa.publicKey(cert), digest, signed,
					si.signature);
				return why == null ? null : "bad " + why;
			}
			if ("EC".equals(kind)) {
				Ec.Curve cv = Ec.curveOf(cert);
				String why = Ec.verify(cv, Ec.publicPoint(cv, cert.keyBits),
					digest, signed, si.signature);
				return why == null ? null : "bad " + why;
			}
		} catch (Der.DerError e) {
			return "refused " + e.getMessage();
		} catch (RuntimeException e) {
			// A corrupted signature reaches BigInteger and the modular
			// inverse of zero is an ArithmeticException. A verifier that
			// dies on attacker-controlled bytes has not said no, it has
			// said nothing.
			return "refused " + e.getClass().getSimpleName() + " while"
				+ " verifying: " + e.getMessage();
		}
		return "refused " + si.encryptionOid + " is neither RSA nor ECDSA";
	}

	/**
	 * Tie the .SF to the manifest.
	 *
	 * The fast path is one digest over the whole manifest file. When
	 * that is absent or stale, which is what happens after something is
	 * added to the manifest since signing, the main attributes digest
	 * and the per-section digests are consulted instead and each section
	 * stands or falls on its own. Both forms appear in the wild and the
	 * difference decides whether an added section is covered.
	 */
	private void link(Signer out, Jar.Sig s) {
		if (!out.sigStatus.equals("ok")) {
			out.linkStatus = "none";
			return;
		}
		if (s.sf == null || jar.manifestBytes == null) {
			out.linkStatus = "bad no manifest to tie the signature file to";
			return;
		}
		Manifest mf = jar.manifest;
		for (int i = 0; i < s.sf.main.keys.size(); i++) {
			String k = s.sf.main.keys.get(i);
			String alg = suffix(k, "-Digest-Manifest");
			if (alg == null) {
				continue;
			}
			String jca = Digest.jcaName(alg);
			byte[] want = B64.decode(s.sf.main.values.get(i));
			if (jca == null || want == null) {
				continue;
			}
			byte[] got = Digest.of(jca, jar.manifestBytes, 0,
				jar.manifestBytes.length);
			if (got != null && java.util.Arrays.equals(got, want)) {
				out.wholeManifest = true;
				out.linkStatus = "manifest";
				for (Manifest.Section ms : mf.sections) {
					if (ms.name != null) {
						out.authenticated.add(ms.name);
					}
				}
				return;
			}
		}
		// The main attributes digest, when present, must match. A
		// mismatch here is not a missing signature, it is a manifest
		// header that has been edited since it was signed.
		for (int i = 0; i < s.sf.main.keys.size(); i++) {
			String k = s.sf.main.keys.get(i);
			String alg = suffix(k, "-Digest-Manifest-Main-Attributes");
			if (alg == null) {
				continue;
			}
			String jca = Digest.jcaName(alg);
			byte[] want = B64.decode(s.sf.main.values.get(i));
			if (jca == null || want == null) {
				continue;
			}
			if (!matches(jca, want, mf.main)) {
				out.linkStatus = "bad the manifest main attributes do not"
					+ " match the " + alg + "-Digest-Manifest-Main-Attributes"
					+ " in " + s.sfName;
				return;
			}
		}
		int n = 0;
		for (Manifest.Section sec : s.sf.sections) {
			if (sec.name == null) {
				continue;
			}
			Manifest.Section ms = mf.forName(sec.name);
			if (ms == null) {
				problems.add(s.sfName + " digests a section named " + sec.name
					+ " that the manifest does not have");
				continue;
			}
			for (String alg : sec.digestAlgorithms()) {
				String jca = Digest.jcaName(alg);
				byte[] want = B64.decode(sec.get(alg + "-Digest"));
				if (jca == null || want == null) {
					continue;
				}
				if (matches(jca, want, ms)) {
					out.authenticated.add(sec.name);
					n++;
				}
				break;
			}
		}
		out.linkStatus = n > 0 ? "sections"
			: "bad nothing in " + s.sfName + " matches the manifest";
	}

	/**
	 * A section digest, taken over the section bytes with and without
	 * the blank line that ends it.
	 *
	 * The JDK digests the section including its trailing blank line and
	 * keeps a second path that excludes it, for files written by older
	 * tools. Accepting either is what the JDK does; accepting only one
	 * rejects archives that verify everywhere else.
	 */
	private boolean matches(String jca, byte[] want, Manifest.Section sec) {
		byte[] a = Digest.of(jca, jar.manifestBytes, sec.off,
			sec.endWithBlank - sec.off);
		if (a != null && java.util.Arrays.equals(a, want)) {
			return true;
		}
		byte[] b = Digest.of(jca, jar.manifestBytes, sec.off,
			sec.endNoBlank - sec.off);
		return b != null && java.util.Arrays.equals(b, want);
	}

	private static String suffix(String key, String tail) {
		if (key.length() <= tail.length()
				|| !key.regionMatches(true, key.length() - tail.length(),
					tail, 0, tail.length())) {
			return null;
		}
		return key.substring(0, key.length() - tail.length());
	}

	private EntryState entryState(Entry e) {
		EntryState st = new EntryState();
		st.entry = e;
		st.signable = jar.isSignable(e);
		if (!st.signable) {
			return st;
		}
		Manifest.Section ms = jar.manifest == null ? null
			: jar.manifest.forName(e.name);
		st.inManifest = ms != null;
		if (ms == null) {
			st.digest = "-";
			return st;
		}
		byte[] data;
		try {
			data = Data.read(jar.zip, e);
		} catch (Data.BadData bad) {
			st.digest = "unreadable";
			problems.add(bad.getMessage());
			return st;
		}
		boolean any = false;
		boolean strong = false;
		st.digest = "nodigest";
		for (String alg : ms.digestAlgorithms()) {
			String jca = Digest.jcaName(alg);
			byte[] want = B64.decode(ms.get(alg + "-Digest"));
			if (jca == null || want == null) {
				continue;
			}
			any = true;
			strong |= !Digest.weak(jca);
			byte[] got = Digest.of(jca, data, 0, data.length);
			if (got == null || !java.util.Arrays.equals(got, want)) {
				st.digest = "mismatch";
				return st;
			}
		}
		if (!any) {
			return st;
		}
		if (!strong) {
			// Every digest covering this entry is one with practical
			// collisions, so the digests match and say nothing. Refused
			// rather than accepted, and refused rather than reported as
			// unsigned, which is what the JDK does and which reads as
			// "nobody signed this" when somebody did.
			st.digest = "weak";
			return st;
		}
		st.digest = "ok";
		for (Signer s : signers) {
			if (s.usable() && s.authenticated.contains(e.name)) {
				st.by.add(s.subject);
			}
		}
		return st;
	}

	/** EX_OK, EX_BAD, EX_UNSIGNED or EX_REFUSED. */
	public int exitCode() {
		boolean refused = false;
		boolean bad = false;
		for (Signer s : signers) {
			if (s.sigStatus.startsWith("refused")) {
				refused = true;
			} else if (!s.sigStatus.equals("ok")
					|| s.linkStatus.startsWith("bad")) {
				bad = true;
			}
		}
		for (EntryState st : entries) {
			if (st.digest.equals("mismatch")) {
				bad = true;
			} else if (st.digest.equals("unreadable")) {
				// An entry the container will not produce is an entry
				// whose digest cannot be shown to hold, and the
				// manifest says it should. That is a rejection and not
				// a refusal: the question was answered, badly. Saying
				// refused here overstated what jarv did not know, and
				// put 16 corrupted archives in the refused column of
				// the corruption sweep while jarsigner called every one
				// of them a digest error.
				bad = true;
			} else if (st.digest.equals("weak")) {
				refused = true;
			}
		}
		if (bad) {
			return Main.EX_BAD;
		}
		if (refused) {
			return Main.EX_REFUSED;
		}
		if (signers.isEmpty()) {
			return Main.EX_UNSIGNED;
		}
		return Main.EX_OK;
	}
}
