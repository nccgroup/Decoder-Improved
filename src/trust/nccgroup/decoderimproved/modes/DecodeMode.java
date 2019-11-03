package trust.nccgroup.decoderimproved.modes;

import com.google.gson.JsonObject;
import trust.nccgroup.decoderimproved.*;
import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.modifiers.decoders.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

/**
 * Created by j on 12/6/16.
 */
public class DecodeMode extends AbstractModificationMode {
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
        decoderComboBox.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        decoderComboBox.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        decoderComboBox.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);

        // Populate the combobox with values
        for (ByteModifier modifier : decoders) {
            decoderComboBox.addItem(modifier.getName());
        }

        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);

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

    public byte[] modifyBytes(byte[] input) throws ModificationException {
        return getSelectedMode().modifyBytes(input);
    }

    public JsonObject toJSON() {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("d", (String) decoderComboBox.getSelectedItem());
        return jsonObject;
    }

    public void setFromJSON(JsonObject jsonObject) {
        try {
            decoderComboBox.setSelectedItem(jsonObject.get("d").getAsString());
        } catch (Exception e) {
            Logger.printErrorFromException(e);
        }
    }
}

