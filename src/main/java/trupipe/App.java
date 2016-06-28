package trupipe;

import coderslagoon.tclib.container.Header;
import coderslagoon.tclib.crypto.AES256;
import coderslagoon.tclib.crypto.BlockCipher;
import coderslagoon.tclib.crypto.Hash;
import coderslagoon.tclib.crypto.RIPEMD160;
import coderslagoon.tclib.crypto.SHA512;
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
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import static java.lang.Compiler.command;
import java.lang.ProcessBuilder.Redirect;
import java.util.StringTokenizer;

public class App {

    public static void main(String[] args) throws TCLibException, IOException {
        String arg, out = null, pwd = null, in = null;
        Class<? extends Hash.Function> hash = null;
        Class<? extends BlockCipher> cipher = null;
        long volSize = -1L;
        int backupHeader = -1;
        Header.Type type = null;
        Iterator<String> argv = Arrays.stream(args).iterator();
        for (int dash = 0; argv.hasNext();) {
            arg = argv.next();
            if (dash > 1 || !arg.startsWith("-")) {
                if (in == null) {
                    in = arg;
                } else if (out == null) {
                    out = arg;
                } else {
                    throw new RuntimeException(String.format("Invalid Argument \"%s\"\n", arg));
                }
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
            } else if (arg.equals("--ripemd160")) {
                hash = RIPEMD160.class;
            } else if (arg.equals("--sha512")) {
                hash = SHA512.class;
            } else if (arg.equals("--vera")) {
                type = Header.Type.VERACRYPT;
            } else if (arg.equals("--backup-header")) {
                backupHeader = 1;
            } else if (arg.equals("--no-backup-header")) {
                backupHeader = 0;
            } else {
                System.err.format("Invalid Argument \"%s\"\n", arg);
                System.exit(1);
            }
        }
        // Hash
        if (hash == null) {
            hash = SHA512.class;
        }
        // Cipher
        if (cipher == null) {
            cipher = AES256.class;
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
            if (in.equals("|")) {
                in = System.console().readLine("Command> ");
            } else {
                in = in.substring(1);
            }
            System.err.format("Source: command \"%s\"\n", in);
            StringTokenizer st = new StringTokenizer(in);
            String[] cmdarray = new String[st.countTokens()];
            for (int i = 0; st.hasMoreTokens(); i++) {
                cmdarray[i] = st.nextToken();
            }
            Process p = new ProcessBuilder(cmdarray).redirectInput(Redirect.INHERIT).redirectError(Redirect.INHERIT).start();
            si = new BufferedInputStream(p.getInputStream());
//            si = new BufferedInputStream(Runtime.getRuntime().exec(in).getInputStream());
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
        // Type
        if (type == null) {
            type = Header.Type.TRUECRYPT;
        }
        // Header
        Header hdr;
        hdr = new Header(type, hash, cipher);
        hdr.version = type.lowestHeader;
        hdr.minimumVersion = type.lowestApp;
        hdr.sizeofHiddenVolume = 0L;
        hdr.dataAreaOffset = Header.OFS_DATA_AREA;
        hdr.sizeofVolume = volSize;
        hdr.dataAreaSize = volSize;
        hdr.flags = 0;
        hdr.reserved3 = null;
        hdr.hiddenVolumeHeader = null;
//        System.err.println(hdr.toString());
        System.err.format("%s %s/%s\n", new String(type.magic), hdr.hashFunction.getSimpleName(), hdr.blockCipher.getSimpleName());
        // Write
        TruPipe.write(pass, so, si, hdr, upt, backupHeader);
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

    public Process  [More ...] exec(String command, String[] envp, File dir)
        throws IOException {
        if (command.length() == 0)
            throw new IllegalArgumentException("Empty command");
        StringTokenizer st = new StringTokenizer(command);
        String[] cmdarray = new String[st.countTokens()];
        for (int i = 0; st.hasMoreTokens(); i++)
            cmdarray[i] = st.nextToken();
        return exec(cmdarray, envp, dir);
    }
 */
