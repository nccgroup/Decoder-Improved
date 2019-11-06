package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPOutputStream;

/**
 * Created by j on 12/6/16.
 */
public class GZIPEncoder implements ByteModifier {
    @Override
    public String getModifierName() {
        return "GZIP";
    }

    // GZIP Encode the bytes
    @Override
    public byte[] modifyBytes(byte[] input) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length);
            GZIPOutputStream gos;
            gos = new GZIPOutputStream(bos);
            gos.write(input, 0, input.length);
            gos.finish();
            gos.flush();
            bos.flush();
            gos.close();
            bos.close();
            return bos.toByteArray();
        } catch (IOException e) {
            Logger.printErrorFromException(e);
            return input;
        }
    }
}

