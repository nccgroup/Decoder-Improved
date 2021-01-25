package trust.nccgroup.decoderimproved;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.exbin.utils.binary_data.BinaryData;


/**
 * Created by j on 10/26/16.
 */

public class Utils {
    // Replacement Char: UTF-8 EFBFBD (U+FFFD)
    private final static String REPLACEMENT_CHAR_STRING = new String(Character.toChars(0xFFFD));
    // Currently only U+FFFF has been identified that breaks Java Swing (in JTextPane)
    private final static String BROKEN_NON_CHARACTER_REGEX = "[\uFFFF]";

    private final static CharsetDecoder UTF8_DECODER = StandardCharsets.UTF_8
            .newDecoder()
            .replaceWith(REPLACEMENT_CHAR_STRING)
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE);

    public static String newUTF8String(byte[] input) {
        try {
            return UTF8_DECODER.decode(ByteBuffer.wrap(input)).toString();
        } catch (CharacterCodingException e) {
            Logger.printErrorFromException(e);
            return "";
        }
    }

    // UTF-8 non-characters (at least U+FFFF) are not supported by Java Swing, which should be replaced with the replacement char
    // https://en.wikipedia.org/wiki/Specials_(Unicode_block)
    // https://stackoverflow.com/a/16619933
    // NOTE: NOT ALL non-characters are replaced, but only those broken in Java Swing
    public static String replaceBrokenNonCharacters(String input) {
        return input.replaceAll(BROKEN_NON_CHARACTER_REGEX, REPLACEMENT_CHAR_STRING);
    }

    public static String convertByteArrayToHexString(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static byte[] convertHexDataToByteArray(BinaryData data) {
        int dataLength = (int) data.getDataSize();
        byte[] output = new byte[dataLength];
        try {
            data.copyToArray(0, output, 0, output.length);
        } catch (Exception e) {
            Logger.printErrorFromException(e);
        }
        return output;
    }

    public static boolean isHexDigit(char c) {
        return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }

    public static byte[] convertByteArrayListToByteArray(List<Byte> input) {
        byte[] bytes = new byte[input.size()];
        for (int i = 0; i < input.size(); i++) {
            bytes[i] = input.get(i);
        }
        return bytes;
    }

    // iterate over array and return true if the list contains search
    public static boolean contains(byte[] array, byte search) {
        for (byte b : array) {
            if (b == search) {
                return true;
            }
        }
        return false;
    }

    // Converts Url byte[] to normal byte[] by replacing the chars
    // "-" (0x2D) -> "+" (0x2B)
    // "_" (0x5F) -> "/" (0x2F)
    // Because we just want to two simple replaces we can just iterate over the byte array
    public static byte[] convertUrlBase64ToStandard(byte[] input) {
        byte[] output = Arrays.copyOf(input, input.length);
        for (int i = 0; i < output.length; i++) {
            if (output[i] == 0x2D) {
                // this just looks cooler than a simple replacement
                // input[i] = input[i] - 0x02 
                output[i] = 0x2B;
            } else if (output[i] == 0x5F) {
                // input[i] = input[i] - 0x30
                output[i] = 0x2F;
            }
        }
        return output;
    }

    public static byte[] removeLeadingAndTrailingWhitespace(byte[] input) {
        int start = 0, end = input.length - 1;
        // Find the first non-whitespace byte
        while(start < input.length && (input[start] == 0x20 || input[start] == 0x09 || input[start] == 0x0D || input[start] == 0x0A)) {
            start++;
        }
        // Find the last non-whitespace byte
        while(end >= 0 && (input[end] == 0x20 || input[end] == 0x09 || input[end] == 0x0D || input[end] == 0x0A)) {
            end--;
        }
        if (start <= end) {
            return Arrays.copyOfRange(input, start, end + 1);
        } else {
            // return empty byte array if there's no whitespace byte
            return new byte[0];
        }
    }

    // Taken from http://stackoverflow.com/questions/28890907/implement-a-function-to-check-if-a-string-byte-array-follows-utf-8-format
    public static int multibyteExpectLength(byte b) {
        int expectedLength = -1;
        if ((b & 0b10000000) == 0b00000000) {
            expectedLength = 1;
        } else if ((b & 0b11100000) == 0b11000000) {
            expectedLength = 2;
        } else if ((b & 0b11110000) == 0b11100000) {
            expectedLength = 3;
        } else if ((b & 0b11111000) == 0b11110000) {
            expectedLength = 4;
        } else if ((b & 0b11111100) == 0b11111000) {
            expectedLength = 5;
        } else if ((b & 0b11111110) == 0b11111100) {
            expectedLength = 6;
        }
        return expectedLength;
    }

    // Input bytes should consist of a valid start byte (0xxxxxxx/110xxxxx/1110xxxx/11110xxx)
    // and multiple (0..n) byte in 10000000 - 10111111
    public static boolean isUTF8Char(byte[] bytes) {
        int count = multibyteExpectLength(bytes[0]);
        if (bytes.length != count) {
            return false;
        }
        for (int i = 1; i < bytes.length; i++) {
            if (bytes[i] > -65) {
                return false;
            }
        }
        return true;
    }

    // https://stackoverflow.com/a/2591122
    public static int getJavaVersion() {
        String version = System.getProperty("java.version");
        if(version.startsWith("1.")) {
            version = version.substring(2, 3);
        } else {
            int dot = version.indexOf(".");
            if(dot != -1) { version = version.substring(0, dot); }
        } return Integer.parseInt(version);
    }
}
