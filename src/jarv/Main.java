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
			} else {
				System.err.println("jarv: --" + m + " is not implemented yet");
				return EX_REFUSED;
			}
		}
		return EX_OK;
	}

	static void dumpZip(Zip z, PrintStream out) {
		out.printf("eocd off=%d entries=%d cdoff=%d cdsize=%d comment=%d%n",
			z.eocdOff, z.cdCount, z.cdOff, z.cdSize, z.commentLen);
		int i = 0;
		for (Entry e : z.entries()) {
			out.printf("cen %d flags=0x%04x method=%d crc=%08x csize=%d usize=%d"
					+ " loff=%d extra=%d utf8=%d name=%s%n",
				i, e.flags, e.method, e.crc, e.compSize, e.uncompSize,
				e.localOff, e.extra.length, e.utf8Name() ? 1 : 0, e.name);
			i++;
		}
	}
}
