package trust.nccgroup.decoderimproved;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

/**
 * Created by j on 12/6/16.
 */
public class DecodeMode extends ModificationMode {
    // ArrayList containing all the different encoders
    private ArrayList<ByteModifier> decoders;

    // Swing components
    private JComboBox<String> decoderComboBox;
    private JPanel comboBoxPanel;

    public DecodeMode() {
        super("Decode as...");

        decoders = new ArrayList<>();
        // All decoders go here
        decoders.add(new PlaintextDecoder());
        decoders.add(new URLDecoder());
        decoders.add(new HTMLDecoder());
        decoders.add(new Base64Decoder());
        decoders.add(new FuzzyBase64Decoder());
        decoders.add(new ASCIIHexDecoder());
        decoders.add(new GZIPDecoder());
        decoders.add(new ZlibDecoder());

        // Swing Components
        decoderComboBox = new JComboBox<>();
        decoderComboBox.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        decoderComboBox.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        decoderComboBox.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));

        // Populate the combobox with values
        for (ByteModifier modifier : decoders) {
            decoderComboBox.addItem(modifier.getName());
        }

        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(new Dimension(180, 40));
        comboBoxPanel.setMinimumSize(new Dimension(180, 40));
        comboBoxPanel.setPreferredSize(new Dimension(180, 40));

        comboBoxPanel.add(decoderComboBox);
        ui.add(comboBoxPanel);
    }

    private ByteModifier getSelectedMode() {
        for (ByteModifier modifier : decoders) {
            if (modifier.getName() == decoderComboBox.getSelectedItem()) {
                return modifier;
            }
        }
        // return the first decoder as a default
        return decoders.get(0);
    }

    public byte[] modifyBytes(byte[] input) throws ModificationException{
        return getSelectedMode().modifyBytes(input);
    }
}

