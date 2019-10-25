package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

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

    // This is for when the text editor is updating the decoder segment state
    public boolean insertUpdateIntoByteArrayList(String input, int offset) {
        // I turn the input string into bytes so I can correctly input all the bytes
        // then I add those bytes to byteArrayList
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        int inputOffset = Utils.calculateByteOffset(getByteArray(), offset);
        for (int i = 0; i < inputBytes.length; i++) {
            byteArrayList.add(i + inputOffset, inputBytes[i]);
        }
        return true;
    }

    // This is for when the text editor is removing characters from the byteArrayList
    public void removeUpdateFromByteArrayList(int offset, int length) {
        // So this chunk of code gets the substring that was removed
        // I then turn that into bytes so i know how many bytes needs to be removed
        // to keep this update in sync with byteArrayList
        // try {
        // I need to calculate the correct offsets based on the actual underlying bytes
        byte[] byteArray = getByteArray();
        int deleteOffset = Utils.calculateByteOffset(byteArray, offset);
        int charsRemovedLength = Utils.calculateByteOffset(byteArray, offset + length) - deleteOffset;
        for (int i = 0; i < charsRemovedLength; i++) {
            byteArrayList.remove(deleteOffset);
        }
    }
}
