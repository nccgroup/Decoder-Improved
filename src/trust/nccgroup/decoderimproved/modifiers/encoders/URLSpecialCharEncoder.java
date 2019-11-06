package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.Utils;

import java.nio.charset.StandardCharsets;

/**
 * Created by j on 12/6/16.
 */
public class URLSpecialCharEncoder implements ByteModifier {
    @Override
    public String getModifierName() {
        return "URL Special Characters";
    }

    // URL Encode the bytes
    @Override
    public byte[] modifyBytes(byte[] input) {
        String letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String numbers = "0123456789";
        String specialChars = "$-_.+!*'(),,";
        byte[] whitelist = (letters + numbers + specialChars).getBytes(StandardCharsets.UTF_8);

        StringBuilder output = new StringBuilder();
        for (byte b : input) {
            if (!Utils.contains(whitelist, b)) {
                output.append("%");
                output.append(String.format("%02X", (0xFF & (int) b)));
            } else {
                output.append((char) b);
            }
        }
        return output.toString().getBytes(StandardCharsets.UTF_8);
    }
}
