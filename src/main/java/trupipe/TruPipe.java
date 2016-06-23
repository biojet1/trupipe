package trupipe;

import coderslagoon.tclib.container.Header;
import coderslagoon.tclib.container.Volume;
import coderslagoon.tclib.crypto.AES256;
import coderslagoon.tclib.crypto.BlockCipher;
import coderslagoon.tclib.crypto.RIPEMD160;
import coderslagoon.tclib.crypto.Rand;
import coderslagoon.tclib.util.Password;
import coderslagoon.tclib.util.TCLibException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.function.Supplier;

public class TruPipe {

    public static void main(final Password pass, final OutputStream so, InputStream si, final long volSize, final Supplier<RandomAccessFile> upd) throws TCLibException, IOException {
        Rand rnd = Rand.wrap(Rand.secure());
        Header hdr = new Header(Header.Type.TRUECRYPT, RIPEMD160.class, AES256.class);
        hdr.generateSalt(rnd);
        hdr.generateKeyMaterial(rnd);
        rnd.make(hdr.salt);
        hdr.sizeofHiddenVolume = 0L;
        hdr.dataAreaOffset = Header.OFS_DATA_AREA;
        hdr.sizeofVolume = volSize;
        hdr.dataAreaSize = volSize;
        hdr.flags = 0;
        hdr.reserved3 = null;
        hdr.hiddenVolumeHeader = null;
        hdr.version = Header.Type.TRUECRYPT.lowestHeader;
        hdr.minimumVersion = Header.Type.TRUECRYPT.lowestApp;
        try {
            // Main header
            byte[] buf = hdr.encode(pass.data());
            long blk = 0;
            System.err.format("@%d Main header, %d bytes %d blocks\n", blk,
                    buf.length, buf.length / Header.BLOCK_SIZE);
            so.write(buf);
            // Data
            Volume vol = new Volume(BlockCipher.Mode.ENCRYPT, hdr);
            blk = (buf.length / vol.blockSize());
            buf = new byte[vol.blockSize()];
            System.err.format("@%d Volume, %d bytes / blocks\n", blk,
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
                        System.err.format("@%d Padding %d off, %d len\n",
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
                blk += (buf.length / vol.blockSize());
            }
            System.err.format("@%d Writen Data %d bytes %d blocks\n", blk, volSizeActual, volSizeActual / vol.blockSize());
            // Backup header
            hdr.sizeofVolume = volSizeActual;
            hdr.dataAreaSize = volSizeActual;
            hdr.generateSalt(rnd);
            buf = hdr.encode(pass.data());
            System.err.format("@%d Backup header, %d bytes %d blocks\n", blk,
                    buf.length, buf.length / Header.BLOCK_SIZE);
            blk += (buf.length / vol.blockSize());
            vol.erase();
            so.write(buf);
            so.flush();
            //
            if (volSize != volSizeActual) {
                System.err.format("@%d Volume size mismatch %d != %d\n", blk,
                        volSize, volSizeActual);
                if (upd != null) {
                    so.close();
                    try (RandomAccessFile rw = upd.get()) {
                        hdr.generateSalt(rnd);
                        buf = hdr.encode(pass.data());
                        System.err.format("@%d Main header, %d bytes %d blocks\n", 0,
                                buf.length, buf.length / Header.BLOCK_SIZE);
                        rw.write(buf);
                    }
                }
            }
        } finally {
            hdr.erase();
            pass.erase();
        }
    }
}
/*
K:\wrx\java\mkimg\bin\mkimg.cmd K:\app\nt\BootICE -o - --hd | K:\wrx\java\trupipe\bin\trupipe.cmd  --in - --out C:/temp/udf.enc --pass 123

K:\wrx\java\trupipe\bin\trupipe.cmd  --in "|cmd /c K:\wrx\java\mkimg\bin\mkimg.cmd K:\app\nt\BootICE -o - --hd" --out C:/temp/udf.enc --pass 123
 */
