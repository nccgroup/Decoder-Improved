package trust.nccgroup.decoderimproved;

import java.util.Base64;

/**
 * Based on Base64Encoder.java
 * We could also use the base64 encoder and substitute the output
 */
public class Base64UrlEncoder extends ByteModifier {
    public Base64UrlEncoder() {
        super("Base64 URL Safe");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) {
        Base64.Encoder encoder = Base64.getUrlEncoder();
        return encoder.encode(input);
    }
}

