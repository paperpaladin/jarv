package jarv;

import java.util.ArrayList;
import java.util.List;

/**
 * A jar: the container, plus the META-INF files a signature lives in.
 *
 * Signature-related names are matched case-insensitively against the
 * directory META-INF only, and only one level deep. That is the rule the
 * JDK uses and it matters: META-INF/foo/bar.SF is an ordinary entry, and
 * meta-inf/X.SF on a case-insensitive filesystem is not.
 */
public final class Jar {
	public final Zip zip;
	/** Raw MANIFEST.MF bytes, or null. */
	public byte[] manifestBytes;
	public Manifest manifest;
	public String manifestName;
	public final List<Sig> sigs = new ArrayList<Sig>();
	public final List<String> problems = new ArrayList<String>();

	/** One signer: a .SF file and the block that signs it. */
	public static final class Sig {
		public String sfName;
		public byte[] sfBytes;
		public Manifest sf;
		public String blockName;
		public byte[] blockBytes;
		/** RSA, DSA or EC, from the block's extension. */
		public String blockKind;
	}

	public Jar(Zip zip) {
		this.zip = zip;
		for (Entry e : zip.entries()) {
			if (e.name.equals("META-INF/MANIFEST.MF")) {
				manifestName = e.name;
				manifestBytes = read(e);
				if (manifestBytes != null) {
					manifest = new Manifest(manifestBytes);
				}
			}
		}
		for (Entry e : zip.entries()) {
			String n = e.name;
			if (!isMetaInfFile(n) || !endsIgnoreCase(n, ".SF")) {
				continue;
			}
			Sig s = new Sig();
			s.sfName = n;
			s.sfBytes = read(e);
			if (s.sfBytes != null) {
				s.sf = new Manifest(s.sfBytes);
			}
			String stem = n.substring(0, n.length() - 3);
			for (String ext : new String[] {".RSA", ".DSA", ".EC"}) {
				Entry b = findIgnoreCase(stem + ext);
				if (b != null) {
					s.blockName = b.name;
					s.blockBytes = read(b);
					s.blockKind = ext.substring(1);
					break;
				}
			}
			if (s.blockName == null) {
				problems.add(n + " has no .RSA, .DSA or .EC block beside it");
			}
			sigs.add(s);
		}
		for (Entry e : zip.entries()) {
			String n = e.name;
			if (isMetaInfFile(n) && (endsIgnoreCase(n, ".RSA")
					|| endsIgnoreCase(n, ".DSA") || endsIgnoreCase(n, ".EC"))) {
				boolean claimed = false;
				for (Sig s : sigs) {
					if (n.equals(s.blockName)) {
						claimed = true;
					}
				}
				if (!claimed) {
					problems.add(n + " is a signature block with no .SF file");
				}
			}
		}
	}

	private Entry findIgnoreCase(String name) {
		for (Entry e : zip.entries()) {
			if (e.name.equalsIgnoreCase(name)) {
				return e;
			}
		}
		return null;
	}

	private byte[] read(Entry e) {
		try {
			return Data.read(zip, e);
		} catch (Data.BadData bad) {
			problems.add(bad.getMessage());
			return null;
		}
	}

	/** META-INF/X with no further slash. */
	public static boolean isMetaInfFile(String n) {
		if (n.length() <= 9) {
			return false;
		}
		if (!n.regionMatches(true, 0, "META-INF/", 0, 9)) {
			return false;
		}
		return n.indexOf('/', 9) < 0;
	}

	static boolean endsIgnoreCase(String s, String suffix) {
		return s.length() >= suffix.length()
			&& s.regionMatches(true, s.length() - suffix.length(), suffix, 0,
				suffix.length());
	}

	/**
	 * Entries a signature can cover.
	 *
	 * Directories are not signed, and neither is the signature machinery
	 * itself: the manifest, every .SF and every block are excluded by the
	 * spec, so an entry missing from the manifest is only interesting when
	 * it is not one of those.
	 */
	public boolean isSignable(Entry e) {
		if (e.isDirectory()) {
			return false;
		}
		String n = e.name;
		if (n.equalsIgnoreCase("META-INF/MANIFEST.MF")) {
			return false;
		}
		if (isMetaInfFile(n) && (endsIgnoreCase(n, ".SF") || endsIgnoreCase(n, ".RSA")
				|| endsIgnoreCase(n, ".DSA") || endsIgnoreCase(n, ".EC"))) {
			return false;
		}
		return true;
	}
}
