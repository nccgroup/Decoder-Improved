package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;

import java.util.Base64;

/**
 * Based on Base64Encoder.java
 * We could also use the base64 encoder and substitute the output
 */
public class Base64UrlEncoder implements ByteModifier {
    public String getName() {
        return "Base64 URL Safe";
    }

    public byte[] modifyBytes(byte[] input) {
        Base64.Encoder encoder = Base64.getUrlEncoder();
        return encoder.encode(input);
    }
}

