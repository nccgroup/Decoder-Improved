package trust.nccgroup.decoderimproved;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DeflaterOutputStream;

public class ZlibEncoder  extends ByteModifier {
    public ZlibEncoder() {
        super("Zlib");
    }

    @Override
    public byte[] modifyBytes(byte[] input) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length);
            DeflaterOutputStream deflater = new DeflaterOutputStream(bos);
            deflater.write(input, 0, input.length);
            deflater.finish();
            deflater.flush();
            bos.flush();
            deflater.close();
            bos.close();
            return bos.toByteArray();
        } catch (IOException e) {
            byte [] empty = {};
            return empty;
        }
    }
}
