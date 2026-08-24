import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * The container as java.util.zip.ZipFile sees it.
 *
 * Named in PLAN.md as the weakest oracle in the list and kept separate
 * for that reason: it ships with jarsigner, so it is a second opinion
 * and not an independent one. What it is good for is the places where
 * it and Info-ZIP disagree, because those are the archives where a
 * verifier's answer depends on which reader it has underneath. The
 * corpus has one: zip64-dd.jar, which Info-ZIP reads and the JDK
 * refuses outright.
 *
 * One line per entry: name, size, compressed size, CRC and method. The
 * CRC is printed from the central directory rather than computed, and
 * the sizes are what the JDK reports after it has resolved whatever
 * zip64 and data descriptors are in play, which is the whole point of
 * asking it.
 */
public final class ZipProbe {
	private ZipProbe() {
	}

	public static void main(String[] args) {
		for (String path : args) {
			try (ZipFile z = new ZipFile(path)) {
				Enumeration<? extends ZipEntry> en = z.entries();
				while (en.hasMoreElements()) {
					ZipEntry e = en.nextElement();
					long read = -1;
					try (InputStream in = z.getInputStream(e)) {
						read = 0;
						byte[] buf = new byte[8192];
						int n;
						while ((n = in.read(buf)) > 0) {
							read += n;
						}
					} catch (Exception ex) {
						read = -1;
					}
					System.out.printf("jdkentry size=%d csize=%d crc=%08x"
							+ " method=%d read=%d name=%s%n",
						e.getSize(), e.getCompressedSize(), e.getCrc(),
						e.getMethod(), read, e.getName());
				}
			} catch (Exception ex) {
				System.out.printf("jdkrefused %s %s%n",
					ex.getClass().getName(), path);
			}
		}
	}
}
