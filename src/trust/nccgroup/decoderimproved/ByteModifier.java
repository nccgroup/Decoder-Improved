package trust.nccgroup.decoderimproved;

import javax.swing.*;

/**
 * Created by j on 12/6/16.
 */
public class ByteModifier extends AbstractByteModifier{
    protected String name;
    protected JPanel ui;

    public ByteModifier() {
        this.name = "";
        ui = new JPanel();
    }

    public ByteModifier(String name) {
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
