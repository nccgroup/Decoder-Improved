package trust.nccgroup.decoderimproved.modifiers.decoders;

/**
 * Created by j on 12/7/16.
 */

import trust.nccgroup.decoderimproved.modifiers.AbstractByteModifier;
import trust.nccgroup.decoderimproved.Utils;

import java.util.ArrayList;
import java.util.Arrays;

public class URLDecoder extends AbstractByteModifier {
    public URLDecoder() {
        super("URL");
    }

    public byte[] modifyBytes(byte[] input) {
        ArrayList<Byte> output = new ArrayList<>();
        for (int i = 0; i < input.length; i++ ) {
            // If the loop is within the last two characters it can't be a url encoded character
            if (i >= input.length-2) {
                output.add(input[i]);
            } else {
                // url encoded chars start with a %
                if (input[i] == '%') {
                    // If the next two chars aren't valid hex chars, it isn't url encoded
                    if (Utils.isHexDigit((char) input[i + 1]) && Utils.isHexDigit((char) input[i + 2])) {
                        // Check if the next two chars after the % are digits
                        // Take in the next two bytes
                        output.add((byte) (Integer.parseInt(new String(Arrays.copyOfRange(input, i + 1, i + 3)), 16) & 0xFF));
                        // Need to skip over the next two characters that were just decoded
                        i += 2;
                    }
                } else {
                    // Add the value of the char
                    output.add(input[i]);
                }
            }
        }
        return Utils.convertByteArrayListToByteArray(output);
    }
}

