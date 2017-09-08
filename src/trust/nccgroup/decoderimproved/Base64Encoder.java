package trust.nccgroup.decoderimproved;

import java.util.Base64;

/**
 * Created by j on 12/6/16.
 */
public class Base64Encoder extends ByteModifier {
    public Base64Encoder() {
        super("Base64");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encode(input);
    }
}

