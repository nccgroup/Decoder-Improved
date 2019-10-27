package trust.nccgroup.decoderimproved;

/**
 * Created by j on 7/27/17.
 */

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FuzzyBase64Decoder extends ByteModifier {

    public FuzzyBase64Decoder() {
        super("Fuzzy Base64");
    }

    // This function uses a regex to extract base64 encoded strings out of the input and decode them.
    // Useful for jwts
    public byte[] modifyBytes(byte[] input) {

        // Convert from Url safe
        String inputString = new String(Utils.convertUrlBase64ToStandard(input), StandardCharsets.UTF_8);
        Pattern p = Pattern.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})");
        Matcher m = p.matcher(inputString);
        ArrayList<Byte> output = new ArrayList<>();

        int startIndex = 0;
        while (m.find()) {
            int matchStart = m.start();
            int matchEnd = m.end();

            for (int i = startIndex; i < matchStart; i++) {
                output.add((byte)inputString.charAt(i));
            }

            String currentBase64edString = inputString.substring(matchStart, matchEnd);
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] currentDecodedString = decoder.decode(currentBase64edString);

            for (byte b : currentDecodedString) {
                output.add(b);
            }

            startIndex = matchEnd;
        }

        for (int i = startIndex; i < inputString.length(); i++) {
            output.add((byte)inputString.charAt(i));
        }

        byte[] outputArray = new byte[output.size()];

        for (int i = 0; i < outputArray.length; i++) {
            outputArray[i] = output.get(i);
        }

        return(outputArray);
    }
}
