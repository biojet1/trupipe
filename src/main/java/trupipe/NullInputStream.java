package trupipe;

import java.io.InputStream;
import java.util.Arrays;

public class NullInputStream extends InputStream {

	@Override
	public int read() {
		return 0;
	}

	@Override
	public int read(byte[] b) {
		Arrays.fill(b, (byte) 0);
		return b.length;
	}

	@Override
	public int read(byte[] b, int off, int len) {
		Arrays.fill(b, off, off + len, (byte) 0);
		return len;
	}
}
