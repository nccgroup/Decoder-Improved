package trust.nccgroup.decoderimproved;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;

/**
 * Created by j on 10/10/16.
 * This file contains the backing Byte Arraylist for every decoder segment
 */

class DecoderSegmentState {
    // I'm going to back this thing with an arraylist for now
    // This is going to get changed to a rope or a data structure that's better
    // for text editors in the future.
    // autoboxing makes me sad
    private final int UNDO_LIMIT = 5;
    private final int REDO_LIMIT = 5;
    enum Action {INSERT, REMOVE, REPLACE};

    private ArrayList<Byte> byteArrayList;
    private ArrayDeque<Command> undoDeque;
    private ArrayDeque<Command> redoDeque;

    public DecoderSegmentState() {
        byteArrayList = new ArrayList<>();
        undoDeque = new ArrayDeque<>();
        redoDeque = new ArrayDeque<>();
    }

    public String getDisplayString() {
        return UTF8StringEncoder.newUTF8String(getByteArray());
    }

    public byte[] getByteArray() {
        return Utils.convertByteArrayListToByteArray(byteArrayList);
    }

    public void setByteArrayList(byte[] data) {
        undoDeque.addLast(new Command(Action.REPLACE, getByteArray(), -1));
        redoDeque.clear();
        resizeDeques();
        replaceBytes(data);
    }

    // This is for when the text editor is updating the decoder segment state
    public void insertUpdateIntoByteArrayList(String input, int offset) {
        // I turn the input string into bytes so I can correctly input all the bytes
        // then I add those bytes to byteArrayList
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        int inputOffset = Utils.calculateByteOffset(getByteArray(), offset);
        insertBytes(inputBytes, inputOffset);
        undoDeque.addLast(new Command(Action.INSERT, inputBytes, inputOffset));
        redoDeque.clear();
        resizeDeques();
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
        byte[] removedBytes = removeBytes(deleteOffset, charsRemovedLength);
        undoDeque.addLast(new Command(Action.REMOVE, removedBytes, deleteOffset));
        redoDeque.clear();
        resizeDeques();
    }

    private void insertBytes(byte[] bytes, int offset) {
        for (int i = 0; i < bytes.length; i++) {
            byteArrayList.add(i + offset, bytes[i]);
        }
    }

    private byte[] removeBytes(int offset, int length) {
        byte[] removedBytes = new byte[length];
        for (int i = 0; i < length; i++) {
            removedBytes[i] = byteArrayList.remove(offset);
        }
        return removedBytes;
    }

    private void replaceBytes(byte[] bytes) {
        byteArrayList.clear();
        for (int i = 0; i < bytes.length; i++) {
            byteArrayList.add(bytes[i]);
        }
    }

    public boolean canUndo() {
        return undoDeque.size() > 0;
    }

    public boolean canRedo() {
        return redoDeque.size() > 0;
    }

    public void undo() {
        if (! undoDeque.isEmpty()) {
            Command undoCommand = undoDeque.removeLast();
            switch (undoCommand.action) {
                case INSERT:
                    removeBytes(undoCommand.offset, undoCommand.diff.length);
                    break;
                case REMOVE:
                    insertBytes(undoCommand.diff, undoCommand.offset);
                    break;
                case REPLACE:
                    byte[] swapDiff = getByteArray();
                    replaceBytes(undoCommand.diff);
                    undoCommand.diff = swapDiff;
                    break;
                default:
                    break;
            }
            redoDeque.addLast(undoCommand);
            resizeDeques();
        }
    }

    public void redo() {
        if (! redoDeque.isEmpty()) {
            Command redoCommand = redoDeque.removeLast();
            switch (redoCommand.action) {
                case INSERT:
                    insertBytes(redoCommand.diff, redoCommand.offset);
                    break;
                case REMOVE:
                    removeBytes(redoCommand.offset, redoCommand.diff.length);
                    break;
                case REPLACE:
                    byte[] swapDiff = getByteArray();
                    replaceBytes(redoCommand.diff);
                    redoCommand.diff = swapDiff;
                    break;
                default:
                    break;
            }
            undoDeque.addLast(redoCommand);
            resizeDeques();
        }
    }

    private void resizeDeques() {
        while (undoDeque.size() > UNDO_LIMIT) {
            undoDeque.removeFirst();
        }
        while (redoDeque.size() > REDO_LIMIT) {
            redoDeque.removeFirst();
        }
    }

    static class Command {
        Action action;
        byte[] diff;
        int offset;
        Command(Action action, byte[] diff, int offset) {
            this.action = action;
            this.diff = diff; // Making use of the original array, assuming that it's not used by any other functions
            this.offset = offset;
        }
    }
}
