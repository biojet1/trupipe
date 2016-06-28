package trupipe;

import coderslagoon.tclib.container.Header;
import coderslagoon.tclib.container.Volume;
import coderslagoon.tclib.crypto.BlockCipher;
import coderslagoon.tclib.crypto.Rand;
import coderslagoon.tclib.util.Password;
import coderslagoon.tclib.util.TCLibException;
import java.util.Arrays;
import java.util.function.Supplier;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;

public class TruPipe {

    public static void write(final Password pass, final OutputStream so, InputStream si, final Header hdr, final Supplier<RandomAccessFile> upd, int backupHeader) throws TCLibException, IOException {
        try {
            Rand rnd = Rand.wrap(Rand.secure());
            hdr.generateSalt(rnd);
            hdr.generateKeyMaterial(rnd);
            rnd.make(hdr.salt);
            long volSize = hdr.sizeofVolume;
            // Main header
            byte[] buf = hdr.encode(pass.data());
            long blk = 0;
            System.err.format("@%9d Main header %dB %d blocks\n", blk,
                    buf.length, buf.length / Header.BLOCK_SIZE);
            so.write(buf);
            // Data
            Volume vol = new Volume(BlockCipher.Mode.ENCRYPT, hdr);
            final int blockSize = vol.blockSize();
            blk = (buf.length / blockSize);
            buf = new byte[blockSize];
            System.err.format("@%9d Data begin %dB/blocks\n", blk,
                    buf.length);
            long volSizeActual = 0;
            while (si != null) {
                int off = 0, r = 0, len = buf.length;
                while ((len > 0) && ((r = si.read(buf, off, len)) > 0)) {
                    off += r;
                    len -= r;
                }

                if (off < buf.length) {
                    if (off > 0) {
                        System.err.format("@%9d Padding %d off %d len\n",
                                blk, off, buf.length);
                        Arrays.fill(buf, off > 0 ? off : 0, buf.length,
                                (byte) 0);
                    } else {
                        assert (r == -1);
                        break;
                    }
                    si = null;
                } else if (r == -1) {
                    break;
                }

                vol.processBlock(blk, buf, 0);
                so.write(buf);
                volSizeActual += buf.length;
                blk += (buf.length / blockSize);
                if ((volSizeActual % (32 * 1024 * 1024)) == 0) {
                    System.err.format("@%9d %.2fMiB... \r", blk, volSizeActual / (1024.0 * 1024.0));
                }
            }
            // Volume done
            vol.erase();
            System.err.format("@%9d Data end %dB %d blocks\n", blk, volSizeActual, volSizeActual / blockSize);
            // Backup header
            if (backupHeader > 0 || (backupHeader < 0 && (volSize != volSizeActual))) {
                hdr.sizeofVolume = volSizeActual;
                hdr.dataAreaSize = volSizeActual;
                hdr.generateSalt(rnd);
                buf = hdr.encode(pass.data());
                System.err.format("@%9d Backup header %dB %d blocks\n", blk,
                        buf.length, buf.length / Header.BLOCK_SIZE);
                blk += (buf.length / blockSize);
                so.write(buf);
            }
            // write done
            so.flush();
            //
            if (volSize != volSizeActual) {
                System.err.format("@%9d Volume size mismatch %d != %d\n", blk,
                        volSize, volSizeActual);
                if (upd != null) {
                    so.close();
                    try (RandomAccessFile rw = upd.get()) {
                        hdr.generateSalt(rnd);
                        buf = hdr.encode(pass.data());
                        System.err.format("@%9d Main header %dB %d blocks\n", 0,
                                buf.length, buf.length / Header.BLOCK_SIZE);
                        rw.write(buf);
                    }
                }
            }
            System.err.format("Done %dB %d blocks\n", blk * blockSize, blk);
        } finally {
            hdr.erase();
            pass.erase();
        }
    }
}
/*
K:\wrx\java\mkimg\bin\mkimg.cmd K:\app\nt\BootICE -o - --hd | K:\wrx\java\trupipe\bin\trupipe.cmd  --in - --out C:/temp/udf.enc --pass 123

trupipe --in "|cmd /c mkimg K:\app\nt\BootICE -o - --hd --manifest" --out C:/temp/udf.enc --pass 123
 */
