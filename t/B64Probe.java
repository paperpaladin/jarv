// An oracle, not part of jarv: java.util.Base64, which is what
// sun.security.util reaches for when it decodes a manifest digest value.
// Compiled by t/run.sh into its scratch directory and never into build/.
// Prints one line per argument: the MIME decoding and the basic decoding,
// or "-" where the decoder throws.
import java.util.Base64;

public class B64Probe {
	public static void main(String[] a) {
		for (String s : a) {
			System.out.println(hex(mime(s)) + " " + hex(basic(s)));
		}
	}

	static byte[] mime(String s) {
		try {
			return Base64.getMimeDecoder().decode(s);
		} catch (RuntimeException e) {
			return null;
		}
	}

	static byte[] basic(String s) {
		try {
			return Base64.getDecoder().decode(s);
		} catch (RuntimeException e) {
			return null;
		}
	}

	static String hex(byte[] b) {
		if (b == null) {
			return "-";
		}
		StringBuilder x = new StringBuilder();
		for (byte v : b) {
			x.append(String.format("%02x", v));
		}
		return x.toString();
	}
}
