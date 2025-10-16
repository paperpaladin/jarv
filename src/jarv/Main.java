package jarv;

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
		+ "            [--entries] [--verify] [--json] FILE.jar";

	public static void main(String[] args) {
		if (args.length == 0) {
			System.err.println(USAGE);
			System.exit(EX_USAGE);
		}
		System.err.println("jarv: not implemented yet");
		System.exit(EX_REFUSED);
	}
}
