package jarv;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/** Command line front end. */
public final class Main {
	/** Exit code for a jar that verifies. */
	public static final int EX_OK = 0;
	/** Exit code for a jar carrying no signature at all. */
	public static final int EX_UNSIGNED = 1;
	/** Exit code for a signed jar that fails verification. */
	public static final int EX_BAD = 2;
	/** Exit code for an input jarv declines to judge. Never an agreement. */
	public static final int EX_REFUSED = 3;
	/** Exit code for a usage error or an unreadable file. */
	public static final int EX_USAGE = 4;

	private Main() {
	}

	private static final String USAGE =
		"usage: jarv [--zip] [--manifest] [--sf] [--der] [--certs]\n"
		+ "            [--entries] [--verify] FILE.jar";

	public static void main(String[] args) {
		List<String> modes = new ArrayList<String>();
		String path = null;
		if (args.length > 0 && args[0].equals("--b64")) {
			// Many values per invocation: the suite compares a few thousand
			// of these against coreutils and a JVM start each would cost
			// more than the rest of the run put together.
			int rc = EX_OK;
			for (int i = 1; i < args.length; i++) {
				byte[] d = B64.decode(args[i]);
				if (d == null) {
					System.out.println("-");
					rc = EX_REFUSED;
				} else {
					System.out.println(Hex.of(d));
				}
			}
			System.exit(rc);
		}
		if (args.length == 2 && args[0].equals("--derfile")) {
			// A raw DER file rather than a jar, so the suite can hold
			// jarv's decoder against openssl asn1parse over crafted
			// encodings that no signer would produce.
			byte[] b;
			try {
				b = Files.readAllBytes(Paths.get(args[1]));
			} catch (IOException e) {
				System.err.println("jarv: " + args[1] + ": " + e.getMessage());
				System.exit(EX_USAGE);
				return;
			}
			try {
				java.util.List<Der.Node> all = new java.util.ArrayList<Der.Node>();
				Der.walk(Der.parse(b), all);
				for (Der.Node n : all) {
					String oid = Der.oid(n);
					System.out.printf("der %d d=%d hl=%d l=%d %s cls=%d tag=%d%s%n",
						n.off, n.depth, n.hl, n.len, n.cons ? "cons" : "prim",
						n.tagClass, n.tag, oid == null ? "" : " oid=" + oid);
				}
			} catch (Der.DerError e) {
				System.err.println("jarv: " + e.getMessage());
				System.exit(EX_REFUSED);
			}
			System.exit(EX_OK);
		}
		for (String a : args) {
			if (a.startsWith("--")) {
				modes.add(a.substring(2));
			} else if (path == null) {
				path = a;
			} else {
				System.err.println("jarv: one file at a time");
				System.exit(EX_USAGE);
			}
		}
		if (path == null) {
			System.err.println(USAGE);
			System.exit(EX_USAGE);
		}
		byte[] file;
		try {
			file = Files.readAllBytes(Paths.get(path));
		} catch (IOException e) {
			System.err.println("jarv: " + path + ": " + e.getMessage());
			System.exit(EX_USAGE);
			return;
		}
		if (modes.isEmpty()) {
			modes.add("verify");
		}
		System.exit(run(modes, file, System.out));
	}

	static int run(List<String> modes, byte[] file, PrintStream out) {
		Zip z = new Zip(file);
		if (z.bad()) {
			System.err.println("jarv: " + z.error());
			return EX_REFUSED;
		}
		for (String m : modes) {
			if (m.equals("zip")) {
				dumpZip(z, out);
			} else if (m.equals("manifest")) {
				if (!dumpManifest(z, out)) {
					return EX_REFUSED;
				}
			} else if (m.equals("der")) {
				if (!dumpDer(new Jar(z), out)) {
					return EX_REFUSED;
				}
			} else if (m.equals("digests")) {
				dumpDigestFacts(new Jar(z), out);
			} else if (m.equals("digest")) {
				if (!dumpDigests(z, out)) {
					return EX_REFUSED;
				}
			} else {
				System.err.println("jarv: --" + m + " is not implemented yet");
				return EX_REFUSED;
			}
		}
		return EX_OK;
	}

	/**
	 * The DER tree of every signature block, in a shape openssl asn1parse
	 * can be compared against node by node.
	 */
	static boolean dumpDer(Jar j, PrintStream out) {
		boolean okAll = true;
		for (Jar.Sig s : j.sigs) {
			if (s.blockBytes == null) {
				continue;
			}
			out.printf("block %s %d%n", s.blockName, s.blockBytes.length);
			try {
				Der.Node root = Der.parse(s.blockBytes);
				java.util.List<Der.Node> all = new java.util.ArrayList<Der.Node>();
				Der.walk(root, all);
				for (Der.Node n : all) {
					String oid = Der.oid(n);
					out.printf("der %d d=%d hl=%d l=%d %s cls=%d tag=%d%s%n",
						n.off, n.depth, n.hl, n.len, n.cons ? "cons" : "prim",
						n.tagClass, n.tag, oid == null ? "" : " oid=" + oid);
				}
			} catch (Der.DerError e) {
				out.printf("derbad %s %s%n", s.blockName, e.getMessage());
				okAll = false;
			}
		}
		return okAll;
	}

	/**
	 * Every digest claim in the jar, with the value jarv computes beside
	 * the value the file declares. The suite checks both against coreutils
	 * rather than against each other.
	 */
	static void dumpDigestFacts(Jar j, PrintStream out) {
		if (j.manifest == null) {
			out.println("nomanifest");
			return;
		}
		for (Manifest.Section s : j.manifest.sections) {
			for (String alg : s.digestAlgorithms()) {
				String jca = Digest.jcaName(alg);
				String declared = s.get(alg + "-Digest");
				byte[] want = jca == null ? null : B64.decode(declared);
				String got = "-";
				Entry e = find(j, s.name);
				if (e != null && jca != null) {
					try {
						byte[] data = Data.read(j.zip, e);
						byte[] d = Digest.of(jca, data, 0, data.length);
						got = d == null ? "-" : Hex.of(d);
					} catch (Data.BadData bad) {
						got = "-";
					}
				}
				out.printf("entrydig %s %s declared=%s computed=%s present=%d %s%n",
					jca == null ? alg : jca, alg,
					want == null ? "-" : Hex.of(want), got,
					e == null ? 0 : 1, s.name);
			}
		}
		for (Jar.Sig sig : j.sigs) {
			if (sig.sf == null) {
				continue;
			}
			for (int i = 0; i < sig.sf.main.keys.size(); i++) {
				String k = sig.sf.main.keys.get(i);
				String suffix = "-Digest-Manifest";
				if (!Jar.endsIgnoreCase(k, suffix)) {
					continue;
				}
				String jca = Digest.jcaName(
					k.substring(0, k.length() - suffix.length()));
				if (jca == null) {
					continue;
				}
				byte[] want = B64.decode(sig.sf.main.values.get(i));
				byte[] whole = Digest.of(jca, j.manifestBytes, 0,
					j.manifestBytes.length);
				out.printf("mfdig %s %s declared=%s whole=%s %s%n",
					sig.sfName, jca, want == null ? "-" : Hex.of(want),
					Hex.of(whole), k);
			}
			for (int i = 0; i < sig.sf.main.keys.size(); i++) {
				String k = sig.sf.main.keys.get(i);
				String suffix = "-Digest-Manifest-Main-Attributes";
				if (!Jar.endsIgnoreCase(k, suffix)) {
					continue;
				}
				String jca = Digest.jcaName(k.substring(0, k.length() - suffix.length()));
				if (jca == null) {
					continue;
				}
				byte[] want = B64.decode(sig.sf.main.values.get(i));
				Manifest.Section ms = j.manifest.main;
				out.printf("maindig %s %s declared=%s withblank=%s noblank=%s%n",
					sig.sfName, jca, want == null ? "-" : Hex.of(want),
					Hex.of(Digest.of(jca, j.manifestBytes, ms.off,
						ms.endWithBlank - ms.off)),
					Hex.of(Digest.of(jca, j.manifestBytes, ms.off,
						ms.endNoBlank - ms.off)));
			}
			for (Manifest.Section s : sig.sf.sections) {
				for (String alg : s.digestAlgorithms()) {
					String jca = Digest.jcaName(alg);
					if (jca == null) {
						continue;
					}
					byte[] want = B64.decode(s.get(alg + "-Digest"));
					Manifest.Section ms = j.manifest.forName(s.name);
					if (ms == null) {
						out.printf("sectdig %s %s declared=%s withblank=- noblank=-"
								+ " %s%n", sig.sfName, jca,
							want == null ? "-" : Hex.of(want), s.name);
						continue;
					}
					out.printf("sectdig %s %s declared=%s withblank=%s noblank=%s"
							+ " %s%n", sig.sfName, jca,
						want == null ? "-" : Hex.of(want),
						Hex.of(Digest.of(jca, j.manifestBytes, ms.off,
							ms.endWithBlank - ms.off)),
						Hex.of(Digest.of(jca, j.manifestBytes, ms.off,
							ms.endNoBlank - ms.off)), s.name);
				}
			}
		}
	}

	private static Entry find(Jar j, String name) {
		for (Entry e : j.zip.entries()) {
			if (e.name.equals(name)) {
				return e;
			}
		}
		return null;
	}

	/** The manifest, section by section, with the byte ranges. */
	static boolean dumpManifest(Zip z, PrintStream out) {
		for (Entry e : z.entries()) {
			if (!e.name.equals("META-INF/MANIFEST.MF")
					&& !(e.name.startsWith("META-INF/") && e.name.endsWith(".SF"))) {
				continue;
			}
			byte[] b;
			try {
				b = Data.read(z, e);
			} catch (Data.BadData bad) {
				out.printf("nodata %s %s%n", e.name, bad.getMessage());
				return false;
			}
			Manifest mf = new Manifest(b);
			out.printf("file %s bytes=%d sections=%d problems=%d%n",
				e.name, b.length, mf.sections.size(), mf.problems.size());
			dumpSection(out, e.name, "-main-", mf.main);
			for (Manifest.Section s : mf.sections) {
				dumpSection(out, e.name, s.name, s);
			}
			for (String p : mf.problems) {
				out.printf("mfproblem %s %s%n", e.name, p);
			}
		}
		return true;
	}

	private static void dumpSection(PrintStream out, String file, String name,
			Manifest.Section s) {
		out.printf("sect %s off=%d endnb=%d endwb=%d attrs=%d name=%s%n",
			file, s.off, s.endNoBlank, s.endWithBlank, s.keys.size(), name);
		for (int i = 0; i < s.keys.size(); i++) {
			out.printf("attr %s %s: %s%n", file, s.keys.get(i), s.values.get(i));
		}
	}

	/** sha256 of every entry's uncompressed bytes, for the oracle to check. */
	static boolean dumpDigests(Zip z, PrintStream out) {
		java.security.MessageDigest md;
		try {
			md = java.security.MessageDigest.getInstance("SHA-256");
		} catch (java.security.NoSuchAlgorithmException e) {
			System.err.println("jarv: no SHA-256: " + e.getMessage());
			return false;
		}
		for (Entry e : z.entries()) {
			byte[] b;
			try {
				b = Data.read(z, e);
			} catch (Data.BadData bad) {
				// One line per entry, and keep going. A reader that stops at
				// the first unreadable member turns eight disagreements into
				// one, and a single comparison over a whole archive is a
				// weaker instrument than one per entry.
				out.printf("nodata %s %s%n", e.name, bad.getMessage());
				continue;
			}
			md.reset();
			out.printf("sha256 %s %d %s%n", Hex.of(md.digest(b)), b.length, e.name);
		}
		return true;
	}

	static void dumpZip(Zip z, PrintStream out) {
		out.printf("eocd off=%d entries=%d cdoff=%d cdsize=%d comment=%d"
				+ " zip64=%d z64off=%d%n",
			z.eocdOff, z.cdCount, z.cdOff, z.cdSize, z.commentLen,
			z.zip64Eocd ? 1 : 0, z.z64Off);
		int i = 0;
		for (Entry e : z.entries()) {
			out.printf("cen %d flags=0x%04x method=%d crc=%08x csize=%d usize=%d"
					+ " loff=%d extra=%d utf8=%d namehex=%s name=%s%n",
				i, e.flags, e.method, e.crc, e.compSize, e.uncompSize,
				e.localOff, e.extra.length, e.utf8Name() ? 1 : 0,
				Hex.of(e.nameBytes), e.name);
			out.printf("loc %d dataoff=%d dd=%d ddsig=%d zip64=%d lmethod=%d"
					+ " lcsize=%d lusize=%d lcrc=%08x mismatch=%d%n",
				i, e.dataOff, e.dataDescriptor ? 1 : 0, e.ddSigned ? 1 : 0,
				e.zip64 ? 1 : 0, e.localMethod, e.localCompSize, e.localUncompSize,
				e.localCrc, z.localMismatches(e).size());
			for (String s : z.localMismatches(e)) {
				out.printf("locbad %d %s%n", i, s);
			}
			i++;
		}
	}
}
