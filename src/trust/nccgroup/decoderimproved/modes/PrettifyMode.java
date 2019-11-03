package trust.nccgroup.decoderimproved.modes;

import com.google.gson.JsonObject;
import trust.nccgroup.decoderimproved.*;
import trust.nccgroup.decoderimproved.modifiers.AbstractByteModifier;
import trust.nccgroup.decoderimproved.modifiers.prettifiers.JsPrettifier;
import trust.nccgroup.decoderimproved.modifiers.prettifiers.XmlPrettifier;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class PrettifyMode extends AbstractModificationMode {
    // Copied from EncodeMode with insignificant adjustments
    private ArrayList<AbstractByteModifier> prettifiers;

    private JComboBox<String> prettifierComboBox;
    private JPanel comboBoxPanel;

    public PrettifyMode() {
        super("Pretty-print...");
        prettifiers = new ArrayList<>();
        prettifiers.add(new XmlPrettifier());
        prettifiers.add(new JsPrettifier());

        prettifierComboBox = new JComboBox<>();
        prettifierComboBox.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        prettifierComboBox.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        prettifierComboBox.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        for (AbstractByteModifier modifier : prettifiers) {
            prettifierComboBox.addItem(modifier.getName());
        }
        prettifierComboBox.setMaximumRowCount(prettifiers.size());
        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(new Dimension(180, 40));
        comboBoxPanel.setMinimumSize(new Dimension(180, 40));
        comboBoxPanel.setPreferredSize(new Dimension(180, 40));
        comboBoxPanel.add(prettifierComboBox);
        ui.add(comboBoxPanel);
    }

    private AbstractByteModifier getSelectedMode() {
        for (AbstractByteModifier modifier : prettifiers) {
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
