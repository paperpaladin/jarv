import java.io.FileInputStream;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * A manifest as java.util.jar.Manifest reads it.
 *
 * The JDK's own parser, and the one jarsigner writes manifests with, so
 * it is the authority on what a folded line is supposed to join back
 * to. It is not independent of the JDK, which is why it is a second
 * opinion rather than the first, but it is independent of the
 * verification path: this class asks what the attribute values are and
 * nothing about signatures.
 *
 * The 72-byte fold is the point. A manifest line is broken at a byte
 * position, which can land in the middle of a UTF-8 sequence, and a
 * reader that decodes each physical line before joining them gets a
 * different answer. Printing the values as UTF-8 and letting the
 * comparison be on the whole string is what makes that visible.
 *
 * Values are printed with the bytes hexed rather than as text, because
 * a value that round-trips through two different notions of "the
 * platform encoding" would otherwise compare equal while differing.
 */
public final class ManifestProbe {
	private ManifestProbe() {
	}

	public static void main(String[] args) throws Exception {
		for (String path : args) {
			Manifest mf;
			try (FileInputStream in = new FileInputStream(path)) {
				mf = new Manifest(in);
			} catch (Exception e) {
				System.out.printf("mfrefused %s %s%n",
					e.getClass().getName(), path);
				continue;
			}
			print("-main-", mf.getMainAttributes());
			for (Map.Entry<String, Attributes> e
					: mf.getEntries().entrySet()) {
				print(e.getKey(), e.getValue());
			}
		}
	}

	private static void print(String section, Attributes a) {
		for (Map.Entry<Object, Object> kv : a.entrySet()) {
			System.out.printf("jdkattr %s %s %s %s%n",
				hex(section), kv.getKey().toString(),
				hex(kv.getValue().toString()), section);
		}
	}

	private static String hex(String s) {
		byte[] b = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		StringBuilder sb = new StringBuilder();
		for (byte x : b) {
			sb.append(String.format("%02x", x & 0xff));
		}
		return sb.toString();
	}
}
