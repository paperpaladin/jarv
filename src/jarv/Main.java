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
