package trust.nccgroup.decoderimproved;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipException;

/**
 * Created by webpentest on 05/2018.
 */
public class ZlibDecoder extends ByteModifier {
    public ZlibDecoder() {
        super("Zlib");
    }

    @Override
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(input);
            InflaterInputStream inflaterStream = new InflaterInputStream(bais);
            byte[] buffer = new byte[input.length*2];
            int bytesRead;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            while ((bytesRead = inflaterStream.read(buffer, 0, buffer.length)) != -1) {
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
