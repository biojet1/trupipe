package trupipe;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.io.File;
import coderslagoon.tclib.container.Header;
import coderslagoon.tclib.container.Header.Type;
import coderslagoon.tclib.container.Volume;
import coderslagoon.tclib.crypto.AES256;
import coderslagoon.tclib.crypto.BlockCipher;
import coderslagoon.tclib.crypto.RIPEMD160;
import coderslagoon.tclib.crypto.Rand;
import coderslagoon.tclib.util.Password;
import coderslagoon.tclib.util.TCLibException;
import java.io.IOException;
import java.util.Iterator;

public class App {

    public static void main(String[] args) {
        Iterator<String> argv = Arrays.stream(args).iterator();
        String arg, out = null, pwd = null, in = null;
        long volSize = -1L;
        for (int dash = 0; argv.hasNext();) {
            arg = argv.next();
            if (dash > 1 || !arg.startsWith("-")) {
                //
            } else if ("--".equals(arg)) {
                dash = 2;
            } else if (arg.equals("--help")) {

            } else if (arg.equals("--version")) {
                System.err.println(App.class.getPackage()
                        .getImplementationVersion());
            } else if (arg.equals("--size") && argv.hasNext()) {
                volSize = Long.parseLong(argv.next());
            } else if (arg.equals("--out") && argv.hasNext()) {
                out = argv.next();
            } else if (arg.equals("--in") && argv.hasNext()) {
                in = argv.next();
            } else if (arg.equals("--pass") && argv.hasNext()) {
                pwd = argv.next();
            } else {
                System.err.format("Invalid Argument \"%s\"\n", arg);
                System.exit(1);
            }
        }

        Password pass = null;
        if ((null == pwd) && (null != (arg = System.getenv("TRUPIPE_PASSWORD"))) && !arg.isEmpty()) {
            pwd = arg;
        } else if ((null == pwd) && (null != (arg = System.getenv("PASSWORD"))) && !arg.isEmpty()) {
            pwd = arg;
        }

        if (null == pwd) {
            throw new RuntimeException("No password");
        } else {
            try {
                pass = new Password(pwd.toCharArray(), null);
            } catch (TCLibException e) {
                throw new RuntimeException(e);
            }
        }

        OutputStream so = null;
        if ((out == null) || out.equals("-")) {
            so = System.out;
            out = "-";
            // ~ System.err.format("Pipe out\n");
        } else if (out.equals("NUL")) {
            so = new NullOutputStream();
        } else {
            try {
                so = new FileOutputStream(out);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
        so = new java.io.BufferedOutputStream(so, 64 * 1024);

        InputStream si = null;
        if ((in == null) || in.equals("-")) {
            si = System.in;
            in = "-";
            // ~ System.err.format("Pipe in\n");
        } else {
            try {
                si = new FileInputStream(in);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
            if (volSize < 0) {
                File f = new File(in);
                volSize = f.length();
            }
        }
        si = new java.io.BufferedInputStream(si, 64 * 1024);

        System.err.format(
                "Encrypt %d bytes, %d bytes/block \"%s\" -> \"%s\"\n", volSize,
                Header.BLOCK_SIZE, in, out);

        if ((volSize < 0) && (null != (arg = System.getenv("TRUPIPE_SIZE"))) && !arg.isEmpty()) {
            volSize = Long.parseLong(arg);
        } else if ((volSize < 0) && (null != (arg = System.getenv("SIZE"))) && !arg.isEmpty()) {
            volSize = Long.parseLong(arg);
        }
        if (volSize < 0) {
            throw new RuntimeException("No Size");
        } else if (volSize < Header.BLOCK_SIZE) {
            throw new RuntimeException("Size too small");
        } else if (volSize > (1125899906842624L - (Header.BLOCK_COUNT
                * Header.BLOCK_SIZE * 2))) {
            throw new RuntimeException("Size too big");
        } else if (0 != (volSize % Header.BLOCK_SIZE)) {
            volSize -= volSize % Header.BLOCK_SIZE;
            System.err.format("Size Adjusted to %d\n", volSize);
        }

        byte[] buf;
        try {
            long blk = 0;
            Rand rnd = Rand.wrap(Rand.secure());

            Header hdr = new Header(Type.TRUECRYPT, RIPEMD160.class, AES256.class);
            // Main header
            hdr.generateSalt(rnd);
            hdr.generateKeyMaterial(rnd);

            rnd.make(hdr.salt);
            hdr.sizeofHiddenVolume = 0L;
            hdr.sizeofVolume = volSize;
            hdr.dataAreaOffset = Header.OFS_DATA_AREA;
            hdr.dataAreaSize = volSize;
            hdr.flags = 0;
            hdr.reserved3 = null;
            hdr.hiddenVolumeHeader = null;
            hdr.version = Header.Type.TRUECRYPT.lowestHeader;
            hdr.minimumVersion = Header.Type.TRUECRYPT.lowestApp;
            // Backup header
            buf = hdr.encode(pass.data());
            System.err.format("@%d Header, %d bytes %d blocks\n", blk,
                    buf.length, buf.length / Header.BLOCK_SIZE);

            so.write(buf);
            blk += (buf.length / Header.BLOCK_SIZE);

            // Data
            Volume vol = new Volume(BlockCipher.Mode.ENCRYPT, hdr);
            long blocks = volSize / Header.BLOCK_SIZE;
            buf = new byte[Header.BLOCK_SIZE];
            System.err.format("@%d Writing Data %d bytes %d blocks\n", blk, volSize,
                    blocks);
            for (; blocks > 0; --blocks) {
                if (null == si) {
                    Arrays.fill(buf, (byte) 0);
                } else {
                    int off = 0, r = 0, len = buf.length;
                    while ((len > 0) && ((r = si.read(buf, off, len)) > 0)) {
                        off += r;
                        len -= r;
                    }
                    if (off < buf.length) {
                        System.err.format("@%d Padding %d off, %d len\n",
                                blk, off, buf.length);
                        Arrays.fill(buf, off > 0 ? off : 0, buf.length,
                                (byte) 0);
                        // si.close();
                        si = null;
                    }
                }
                vol.processBlock(blk, buf, 0);

                so.write(buf);
                blk += (buf.length / Header.BLOCK_SIZE);
            }
            int off = 0, r = 0;
            if ((null != si) && ((r = si.read(buf, 0, buf.length)) > 0)) {
                off += r;
                System.err.format("@%d Cutting Input", blk);
                while (((r = si.read(buf, 0, buf.length)) > 0)) {
                    off += r;
                    System.err.print(".");
                }
                System.err.format("\n");
            }
            // Backup header
            hdr.generateSalt(rnd);
            buf = hdr.encode(pass.data());
            System.err.format("@%d Header, %d bytes %d blocks\n", blk,
                    buf.length, buf.length / Header.BLOCK_SIZE);
            so.write(buf);
            blk += (buf.length / Header.BLOCK_SIZE);
            // Done
            so.close();
            // Check size
            File f = new File(out);
            if (f.exists()) {
                long s1 = f.length();
                long s2 = (Header.BLOCK_COUNT * Header.BLOCK_SIZE) + volSize
                        + (Header.BLOCK_COUNT * Header.BLOCK_SIZE);
                System.err.format("Size of \"%s\" %d %d expected\n", out, s1,
                        s2);
            }
        } catch (TCLibException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
/*
mvn install:install-file -Dfile=trupax.jar -DgroupId=com.coderslagoon -DartifactId=trupax -Dversion=9.0 -Dpackaging=jar

  <dependency>
      <groupId>com.coderslagoon</groupId>
      <artifactId>trupax</artifactId>
      <version>9.0</version>
 </dependency>

 pushd K:\wrx\java\trupipe
 */
