package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
        return UTF8StringEncoder.newUTF8String(getByteArray());
    }

    // Calculate byte offset based on UTF-8 multibyte definition, to support more multibyte characters.
    private int calculateByteOffset(int stringOffset) {
        byte[] bytes = getByteArray();
        int offset = 0;
        for (int i = 0; i < stringOffset; i++) {
            int cur = offset;
            if (cur >= bytes.length)
                break;
            byte b = bytes[cur];
            if (b >= 0) { // single-byte char, in 00000000 - 01111111
                if (b == 13 && cur + 1 < bytes.length && bytes[cur + 1] == 10) { // CRLF \x0d\x0a case
                    offset += 2;
                } else {
                    offset += 1;
                }
            } else if (b <= -33 && b >= -64) { // two-byte char, first byte in 11000000 - 11011111
                offset += multibyteOffset(bytes, cur, 1);
            } else if (b <= -17 && b >= -32) { // three-byte char, first byte in 11100000 - 11101111
                offset += multibyteOffset(bytes, cur, 2);
            } else if (b <= -9 && b >= -16) { // four-byte char, first byte in 11110000 - 11110111
                offset += multibyteOffset(bytes, cur, 3);
            } else { // Unsupported byte
                offset += 1;
            }
        }
        return offset;
    }

    private int multibyteOffset(byte[] bytes, int currentOffset, int maxLength) {
        int byteCount = 0;
        List<Byte> buf = new ArrayList<>();
        for (int j = 0; j <= maxLength; j++) {
            // the second (or third and fourth) byte should in 10000000 - 10111111
            if (currentOffset + j < bytes.length && (j == 0 || bytes[currentOffset + j] <= -65)) {
                byteCount += 1;
                buf.add(bytes[currentOffset + j]);
            } else {
                break;
            }
        }
        int characterCount = UTF8StringEncoder.newUTF8String(Utils.convertByteArrayListToByteArray(buf)).length();
        return byteCount - characterCount + 1;
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
        int charsRemovedLength = calculateByteOffset(offset + length) - deleteOffset;
        for (int i = 0; i < charsRemovedLength; i++) {
            byteArrayList.remove(deleteOffset);
        }
    }
}
