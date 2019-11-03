package trust.nccgroup.decoderimproved.modes;

import com.google.gson.JsonObject;
import trust.nccgroup.decoderimproved.*;
import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.modifiers.prettifiers.JsPrettifier;
import trust.nccgroup.decoderimproved.modifiers.prettifiers.XmlPrettifier;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class PrettifyMode extends AbstractModificationMode {
    // Copied from EncodeMode with insignificant adjustments
    private ArrayList<ByteModifier> prettifiers;

    private JComboBox<String> prettifierComboBox;
    private JPanel comboBoxPanel;

    public PrettifyMode() {
        super("Pretty-print...");
        prettifiers = new ArrayList<>();
        prettifiers.add(new XmlPrettifier());
        prettifiers.add(new JsPrettifier());

        prettifierComboBox = new JComboBox<>();
        prettifierComboBox.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        prettifierComboBox.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        prettifierComboBox.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);
        for (ByteModifier modifier : prettifiers) {
            prettifierComboBox.addItem(modifier.getName());
        }
        prettifierComboBox.setMaximumRowCount(prettifiers.size());
        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.add(prettifierComboBox);
        ui.add(comboBoxPanel);
    }

    private ByteModifier getSelectedMode() {
        for (ByteModifier modifier : prettifiers) {
            if (modifier.getName() == prettifierComboBox.getSelectedItem()) {
                return modifier;
            }
        }
        return prettifiers.get(0);
    }

    public byte[] modifyBytes(byte[] input) throws ModificationException {
        return getSelectedMode().modifyBytes(input);
    }

    public JsonObject toJSON() {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("p", (String) prettifierComboBox.getSelectedItem());
        return jsonObject;
    }

    public void setFromJSON(JsonObject jsonObject) {
        try {
            prettifierComboBox.setSelectedItem(jsonObject.get("p").getAsString());
        } catch (Exception e) {
            Logger.printErrorFromException(e);
        }
    }
}
