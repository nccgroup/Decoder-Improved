package trust.nccgroup.decoderimproved.modifiers.decoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.ModificationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipException;

/**
 * Created by webpentest on 05/2018.
 */
public class ZlibDecoder implements ByteModifier {
    @Override
    public String getModifierName() {
        return "Zlib";
    }

    @Override
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(input);
            InflaterInputStream inflaterStream = new InflaterInputStream(bais);
            byte[] buffer = new byte[input.length*2];
            int bytesRead;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            while ((bytesRead = inflaterStream.read(buffer, 0, buffer.length)) > 0) {
                output.write(buffer, 0, bytesRead);
            }
            return output.toByteArray();
        } catch (ZipException e){
            throw new ModificationException("Invalid Zlib Input");
        } catch (IOException e) {
            throw new ModificationException("IO Error");
        }
    }
}
