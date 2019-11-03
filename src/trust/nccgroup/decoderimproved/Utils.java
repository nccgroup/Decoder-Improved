package trust.nccgroup.decoderimproved;

import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.exbin.utils.binary_data.BinaryData;

import javax.swing.*;


/**
 * Created by j on 10/26/16.
 */

public class Utils {

    public static String convertByteArrayToHexString (byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static byte[] convertHexDataToByteArray(BinaryData data) {
        int dataLength = (int)data.getDataSize();
        byte[] output = new byte[dataLength];
        try {
            data.getDataInputStream().read(output);
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

    public static byte[] extendByteArray(byte[] input, int length) {
        // I'm only using this function in like one spot, this should never happen.
        if (length > 0) {
            return new byte[0];
        }
        byte[] output = new byte[input.length + length];
        System.arraycopy(input, 0, output, 0, input.length);
        return output;
    }
    
    // Converts Url byte[] to normal byte[] by replacing the chars
    // "-" (0x2D) -> "+" (0x2B)
    // "_" (0x5F) -> "/" (0x2F)
    // Because we just want to two simple replaces we can just iterate over the byte array
    public static byte[] convertUrlBase64ToStandard(byte[] input) {
        byte[] output = Arrays.copyOf(input, input.length);
        for (int i = 0; i < output.length ; i ++) {
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

    public static void highlightParentTab(Component tabComponent) {
        if (tabComponent != null) {
            JTabbedPane parentTabbedPane = (JTabbedPane) tabComponent.getParent();
            int index = parentTabbedPane.indexOfComponent(tabComponent);
            parentTabbedPane.setBackgroundAt(index, new Color(0xE58900));
            Timer timer = new Timer(3000, e -> {
                parentTabbedPane.setBackgroundAt(index, Color.BLACK);
            });
            timer.setRepeats(false);
            timer.start();
        }
    }

    // Calculate byte offset based on UTF-8 multibyte definition, to support more multibyte characters.
    public static int calculateByteOffset(byte[] bytes, int stringOffset) {
        int offset = 0;
        for (int i = 0; i < stringOffset; i++) {
            int cur = offset;
            if (cur >= bytes.length)
                break;
            byte b = bytes[cur];
            int expectedLength = multibyteExpectLength(b);
            switch (expectedLength) {
                case 1: // single-byte char, in 00000000 - 01111111
                    if (b == 13 && cur + 1 < bytes.length && bytes[cur + 1] == 10) { // CRLF \x0d\x0a case
                        offset += 2;
                    } else {
                        offset += 1;
                    }
                    break;
                case 2: // two-byte char, first byte in 11000000 - 11011111
                case 3: // three-byte char, first byte in 11100000 - 11101111
                case 4: // four-byte char, first byte in 11110000 - 11110111
                    offset += multibyteOffset(bytes, cur, expectedLength);
                    break;
                default:
                    offset += 1;
                    break;
            }
        }
        return offset;
    }

    private static int multibyteOffset(byte[] bytes, int currentOffset, int maxLength) {
        int byteCount = 0;
        List<Byte> buf = new ArrayList<>();
        for (int i = 0; i < maxLength; i++) {
            // the second (or third and fourth) byte should be in 10000000 - 10111111
            if (currentOffset + i < bytes.length && (i == 0 || bytes[currentOffset + i] <= -65)) {
                byteCount += 1;
                buf.add(bytes[currentOffset + i]);
            } else {
                break;
            }
        }
        int characterCount = UTF8StringEncoder.newUTF8String(Utils.convertByteArrayListToByteArray(buf)).length();
        return byteCount - characterCount + 1;
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
        if (bytes.length != count){
            return false;
        }
        for (int i = 1; i < bytes.length; i++) {
            if (bytes[i] > -65) {
                return false;
            }
        }
        return true;
    }
}
