package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by j on 10/10/16.
 * This file contains the backing Byte Arraylist for every decoder segment
 */

public class DecoderSegmentState {
    // I'm going to back this thing with an arraylist for now
    // This is going to get changed to a rope or a data structure that's better
    // for text editors in the future.
    // autoboxing makes me sad
    private ArrayList<Byte> byteArrayList;

    public DecoderSegmentState() {
        byteArrayList = new ArrayList<>();
    }

    public String getDisplayString() {
        // This is a bad way to do this but it works for now
        // but I need to convert the Byte ArrayList back to a byte[] for new String()
        byte[] output = new byte[byteArrayList.size()];
        for (int i = 0; i < byteArrayList.size(); i++) {
            output[i] = byteArrayList.get(i);
        }
        return UTF8StringEncoder.newUTF8String(output);
    }

    // This is a miracle that this works. If it causes an exception, sorry.
    private int calculateByteOffset(int startIndex) {
        // byte[] replacementChar = Charset.forName("UTF-8").newEncoder().replacement();
        // System.out.print("The Replacement is: ");
        // Utils.printByteArray(replacementChar);
        // System.out.println(new String(replacementChar));
        try {
            String displayString = getDisplayString();
            // If there are no �s in the string, calculating the offset is easy.
            if (!displayString.contains("�")) {
                try {
                    return displayString.substring(0, startIndex).getBytes("UTF-8").length;
                } catch (UnsupportedEncodingException e) {
                    // This should never happen.
                    return -1;
                }
            } else {
                // The underlying bytearray
                byte[] bytes = getByteArray();
                // This is the total offset
                int offset = 0;
                // Iterate over the first 0 -> startIndex chars in displayString
                for (int i = 0; i < startIndex; i++)  {
                    // Check if it's a two byte replacement
                    if (displayString.charAt(i) == '�') {
                        if (offset + 3 <= bytes.length && Utils.charIsReplacementChar(Arrays.copyOfRange(bytes, offset, offset+3))) {
                            offset += 3;
                        } else if (Utils.isTwoByteReplacementStart(bytes[offset])) {
                            if (offset + 1 < bytes.length && Utils.isTwoByteReplacement(bytes[offset], bytes[offset + 1])) {
                                    offset += 2;
                            } else {
                                offset += 1;
                            }
                        } else {
                            offset += 1;
                        }
                    } else {
                        byte[] characterBytes = displayString.substring(i,i+1).getBytes("UTF-8");
                        offset += characterBytes.length;
                    }
                }
                return offset;
            }
        } catch (UnsupportedEncodingException e) {
            // this should never happen
            return -1;
        }
    }

    // This is for when the text editor is updating the decoder segment state
    public boolean insertUpdateIntoByteArrayList(String input, int offset) {
        // I turn the input string into bytes so I can correctly input all the bytes
        // then I add those bytes to byteArrayList
        // System.out.print("The Byte offset is: ");
        // System.out.println(calculateByteOffset(offset));
        try {
            byte[] inputBytes = input.getBytes("UTF-8");
            //int inputOffset = getDisplayString().substring(0, offset).getBytes("UTF-8").length;
            //int inputOffset = calculateByteOffset(0, offset);
            int inputOffset = calculateByteOffset(offset);
            // System.out.print("The offset is: ");
            // System.out.println(offset);
            // System.out.print("The inputOffset is: ");
            // System.out.println(inputOffset);
            for (int i = 0; i < inputBytes.length; i++) {
                // System.out.println(input.charAt(i));
                byteArrayList.add(i + inputOffset, inputBytes[i]);
            }
            return true;
        } catch (UnsupportedEncodingException e ) {
            return false;
        }
    }

    public byte[] getByteArray() {
        return Utils.convertByteArrayListToByteArray(byteArrayList);
    }

    // This is for setting a single byte in the hex editor
    public void setByte(int index, byte data) {
        byteArrayList.set(index, data);
    }

    // I don't know if I'm going to use this yet
    public void setByteArrayList(byte[] data) {
        byteArrayList.clear();
        for (int i = 0; i < data.length; i++) {
            byteArrayList.add(data[i]);
        }
    }

    // This is for when the text editor is removing characters from the byteArrayList
    public void removeUpdateFromByteArrayList(int offset, int length) {
        // So this chunk of code gets the substring that was removed
        // I then turn that into bytes so i know how many bytes needs to be removed
        // to keep this update in sync with byteArrayList
        // try {
        // I need to calculate the correct offsets based on the actual underlying bytes
        int deleteOffset = calculateByteOffset(offset);
        int charsRemovedLength = calculateByteOffset(offset + length)-deleteOffset;
        for (int i = 0; i < charsRemovedLength; i++) {
            byteArrayList.remove(deleteOffset);
        }
    }
}
