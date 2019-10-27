package trust.nccgroup.decoderimproved;

import javax.swing.*;

/**
 * Created by j on 12/6/16.
 */
class ByteModifier extends AbstractByteModifier{
    private String name;
    private JPanel ui;

    ByteModifier() {
        this.name = "";
        ui = new JPanel();
    }

    ByteModifier(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public JPanel getUI () {
        return ui;
    }

    public byte[] modifyBytes(byte[] input) throws ModificationException{
        return input;
    }
}
