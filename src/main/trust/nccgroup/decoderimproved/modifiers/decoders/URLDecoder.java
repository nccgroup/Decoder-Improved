package trust.nccgroup.decoderimproved.modifiers.decoders;

/**
 * Created by j on 12/7/16.
 */

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.Utils;

import java.util.ArrayList;
import java.util.Arrays;

public class URLDecoder implements ByteModifier {
    @Override
    public String getModifierName() {
        return "URL";
    }

    @Override
    public byte[] modifyBytes(byte[] input) {
        ArrayList<Byte> output = new ArrayList<>();
        for (int i = 0; i < input.length; i++ ) {
            // '+' will be decoded as a space character, as per https://www.w3.org/TR/html4/interact/forms.html#h-17.13.4.1
            if(input[i] == '+') {
                output.add((byte) ' ');
            } else if (i < input.length - 2 && input[i] == '%') {
                // If the next two chars aren't valid hex chars, it isn't url encoded
                if (Utils.isHexDigit((char) input[i + 1]) && Utils.isHexDigit((char) input[i + 2])) {
                    // Check if the next two chars after the % are digits
                    // Take in the next two bytes
                    output.add((byte) (Integer.parseInt(new String(Arrays.copyOfRange(input, i + 1, i + 3)), 16) & 0xFF));
                    // Need to skip over the next two characters that were just decoded
                    i += 2;
                }
            } else {
                output.add(input[i]);
            }
        }
        return Utils.convertByteArrayListToByteArray(output);
    }
}

