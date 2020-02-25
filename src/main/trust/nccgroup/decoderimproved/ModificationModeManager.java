package trust.nccgroup.decoderimproved;

import trust.nccgroup.decoderimproved.modes.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;

/**
 * Created by j on 12/6/16.
 */
public class ModificationModeManager {
    private ArrayList<AbstractModificationMode> modes;
    private JPanel ui;
    private JPanel modeUI;
    private CardLayout layoutManager;
    private JComboBox<String> modeComboBox;

    public ModificationModeManager() {
        layoutManager = new CardLayout();
        modeUI = new JPanel(layoutManager);
        ui = new JPanel();
        modes = new ArrayList<>();
        modeComboBox = new JComboBox<>();

        // Swing configuration
        ui.setLayout(new BoxLayout(ui, BoxLayout.PAGE_AXIS));
        ui.setMaximumSize(new Dimension(180, 120));
        ui.setMinimumSize(new Dimension(180, 100));
        ui.setPreferredSize(new Dimension(180, 105));

        modeComboBox.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        modeComboBox.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        modeComboBox.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));

        modeComboBox.addActionListener((ActionEvent e) -> {
            layoutManager.show(modeUI, (String)modeComboBox.getSelectedItem());
            //System.out.print("Selected Item is: ");
//            System.out.println((String)modeComboBox.getSelectedItem());
        });

        ui.add(modeComboBox);
        ui.add(modeUI);

        addMode(new EncodeMode());
        addMode(new DecodeMode());
        addMode(new HashMode());
        addMode(new BaseConvertMode());
        addMode(new FindAndReplaceMode());
        addMode(new PrettifyMode());
        //addMode(new TextReplaceMode());
    }

    private void addMode(AbstractModificationMode mode) {
        modes.add(mode);
        modeComboBox.addItem(mode.getModeName());
        modeUI.add(mode.getUI(), mode.getModeName());
        // System.out.print("getName = ");
        // System.out.println(mode.getName());
        // Show the default mode
        if (modes.size() == 1) {
            layoutManager.show(modeUI, mode.getModeName());
        }
    }

    public ArrayList<AbstractModificationMode> getModes() {
        return modes;
    }

    public JPanel getUI() {
        return ui;
    }

    public AbstractModificationMode getSelectedMode() {
        for (AbstractModificationMode mode : modes) {
            if (mode.getModeName() == modeComboBox.getSelectedItem()) {
                return mode;
            }
        }
        // return the first encoder as a default
        return modes.get(0);
    }

    public void setSelectedMode(String name) {
        modeComboBox.setSelectedItem(name);
    }

    public byte[] modifyBytes(byte[] input) throws ModificationException{
        return getSelectedMode().modifyBytes(input);
    }
}
