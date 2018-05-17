package trust.nccgroup.decoderimproved;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class PrettifyMode extends ModificationMode {
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
        prettifierComboBox.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        prettifierComboBox.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        prettifierComboBox.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        for (ByteModifier modifier : prettifiers) {
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
}
