package trupipe;

import java.util.Arrays;
import java.util.Iterator;
import java.util.function.Supplier;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import coderslagoon.tclib.util.Password;
import coderslagoon.tclib.util.TCLibException;

public class App {

    public static void main(String[] args) throws TCLibException, IOException {
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
            } else if (arg.equals("--block-size") && argv.hasNext()) {
                argv.next();
            } else if (arg.equals("--hash") && argv.hasNext()) {
                argv.next();
            } else if (arg.equals("--algorithm") && argv.hasNext()) {
                argv.next();
            } else {
                System.err.format("Invalid Argument \"%s\"\n", arg);
                System.exit(1);
            }
        }
        // Password
        Password pass = null;
        if ((null == pwd) && (null != (arg = System.getenv("TRUPIPE_PASSWORD"))) && !arg.isEmpty()) {
            pwd = arg;
        } else if ((null == pwd) && (null != (arg = System.getenv("PASSWORD"))) && !arg.isEmpty()) {
            pwd = arg;
        }
        if (null == pwd) {
            try {
                pass = new Password(System.console().readPassword("Password> "), null);
            } catch (TCLibException e) {
                throw new RuntimeException(e);
            }
        } else {
            try {
                pass = new Password(pwd.toCharArray(), null);
            } catch (TCLibException e) {
                throw new RuntimeException(e);
            }
        }
        // Sink
        OutputStream so = null;
        Supplier<RandomAccessFile> upt = null;
        if ((out == null) || out.equals("-")) {
            so = System.out;
            System.err.format("Sink: stdout\n");
        } else if (out.equals("NUL")) {
            so = new NullOutputStream();
            System.err.format("Sink: null\n");
        } else {
            System.err.format("Sink: file %s\n", out);
            try {
                String rwfile = out;
                so = new FileOutputStream(out);
                upt = () -> {
                    try {
                        return new RandomAccessFile(rwfile, "rw");
                    } catch (FileNotFoundException ex) {
                        throw new RuntimeException(ex);
                    }
                };
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
        so = new java.io.BufferedOutputStream(so, 1024 * 1024);
        // Source
        InputStream si = null;
        if ((in == null) || in.equals("-")) {
            si = System.in;
            System.err.format("Source: stdin\n");
        } else if (in.startsWith("|")) {
            in = in.substring(1);
            System.err.format("Source: command \"%s\"\n", in);
            si = Runtime.getRuntime().exec(in).getInputStream();
        } else {
            System.err.format("Source: file %s\n", in);
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
        si = new java.io.BufferedInputStream(si, 1024 * 1024);
        // Write
        TruPipe.main(pass, so, si, volSize, upt);
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
mee --cd  K:\wrx\java\trupipe -- mvn-pe package
 */
