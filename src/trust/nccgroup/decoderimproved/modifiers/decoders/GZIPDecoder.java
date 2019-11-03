package trust.nccgroup.decoderimproved.modifiers.decoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.Logger;
import trust.nccgroup.decoderimproved.ModificationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

/**
 * Created by j on 12/7/16.
 */
public class GZIPDecoder implements ByteModifier {
    public String getName() {
        return "GZIP";
    }

    // GZIP Encode the bytes
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(input);
            GZIPInputStream gzis = new GZIPInputStream(bais);

            byte[] buffer = new byte[input.length * 2];
            int bytesRead;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            while ((bytesRead = gzis.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
            return output.toByteArray();
        } catch (IOException e) {
            Logger.printErrorFromException(e);
            throw new ModificationException("Invalid GZIP Input");
        }
    }
}
