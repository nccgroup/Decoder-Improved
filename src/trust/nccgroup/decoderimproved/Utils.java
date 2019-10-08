package trust.nccgroup.decoderimproved;

import java.awt.*;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.exbin.utils.binary_data.BinaryData;

import javax.swing.*;

/**
 * Created by j on 10/26/16.
 */

public class Utils {
    private static HashSet<List<Byte>> twoByteReplacement;

    static {
        twoByteReplacement = new HashSet<List<Byte>>();
        try {
            for (int i = 0; i <= 0xFF; i++) {
                for (int j = 0; j <= 0xFF; j++) {
                    byte[] bytes = {(byte)i, (byte)j};
                    String displayString = UTF8StringEncoder.newUTF8String(bytes);
                    if(displayString.getBytes("UTF-8").length == 3) {
                        twoByteReplacement.add(Arrays.asList((byte)i, (byte)j));
                    }
                }
            }
        } catch (Exception e) { }
    }

    public static boolean isTwoByteReplacementStart(byte input) {
        return (input >= (byte)0xE0 && input <= (byte)0xF4);
    }

    public static boolean isTwoByteReplacement(byte first, byte second) {
        return twoByteReplacement.contains(Arrays.asList(first, second));
    }

    public static boolean charIsReplacementChar(byte[] b) {
        try {
            byte[] replacementCharByteArray = "�".getBytes("UTF-8");
            for (int i = 0; i < 3; i++) {
                if (b[i] != replacementCharByteArray[i]) {
                    return false;
                }
            }
            return true;
        } catch (UnsupportedEncodingException e) {
            return false;
        }
    }


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
        } catch (Exception e) { }
        return output;
    }

    public static boolean isHexDigit(char c) {
       return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }

    public static byte[] convertByteArrayListToByteArray(ArrayList<Byte> input) {
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

    // Taken from http://stackoverflow.com/questions/28890907/implement-a-function-to-check-if-a-string-byte-array-follows-utf-8-format
    // I don't think I'm going to use this, can probably be removed
    public static boolean isUTF8(final byte[] pText) {

        int expectedLength = 0;

        for (int i = 0; i < pText.length; i++) {
            if ((pText[i] & 0b10000000) == 0b00000000) {
                expectedLength = 1;
            } else if ((pText[i] & 0b11100000) == 0b11000000) {
                expectedLength = 2;
            } else if ((pText[i] & 0b11110000) == 0b11100000) {
                expectedLength = 3;
            } else if ((pText[i] & 0b11111000) == 0b11110000) {
                expectedLength = 4;
            } else if ((pText[i] & 0b11111100) == 0b11111000) {
                expectedLength = 5;
            } else if ((pText[i] & 0b11111110) == 0b11111100) {
                expectedLength = 6;
            } else {
                return false;
            }

            while (--expectedLength > 0) {
                if (++i >= pText.length) {
                    return false;
                }
                if ((pText[i] & 0b11000000) != 0b10000000) {
                    return false;
                }
            }
        }

        return true;
    }

    public static byte[] extendByteArray(byte[] input, int length) {
        // I'm only using this function in like one spot, this should never happen.
        if (length > 0) {
            return new byte[0];
        }
        byte[] output = new byte[input.length+length];
        for (int i = 0; i < input.length; i ++) {
            output [i] = input[i];
        }
        return output;
    }
    
    // Converts Url byte[] to normal byte[] by replacing the chars
    // "-" (0x2D) -> "+" (0x2B)
    // "_" (0x5F) -> "/" (0x2F)
    // Because we just want to two simple replaces we can just iterate over the byte array
    public static byte[] convertUrlBase64ToStandard(byte[] input) {
        for (int i = 0; i < input.length ; i ++) {
            if (input[i] == 0x2D) {
                // this just looks cooler than a simple replacement
                // input[i] = input[i] - 0x02 
                input[i] = 0x2B;
            } else if (input[i] == 0x5F) {
                // input[i] = input[i] - 0x30
                input[i] = 0x2F;
            }
        }
        return input;
    }

    public static void highlightParentTab(JTabbedPane parentTabbedPane, Component childComponent) {
        if (parentTabbedPane != null) {
            for (int i = 0; i < parentTabbedPane.getTabCount(); i++) {
                if (parentTabbedPane.getComponentAt(i).equals(childComponent)) {
                    parentTabbedPane.setBackgroundAt(i, new Color(0xE58900));
                    Timer timer = new Timer(3000, e -> {
                        for (int j = 0; j < parentTabbedPane.getTabCount(); j++) {
                            if (parentTabbedPane.getComponentAt(j).equals(childComponent)) {
                                parentTabbedPane.setBackgroundAt(j, Color.BLACK);
                                break;
                            }
                        }
                    });
                    timer.setRepeats(false);
                    timer.start();
                    break;
                }
            }
        }
    }
}
