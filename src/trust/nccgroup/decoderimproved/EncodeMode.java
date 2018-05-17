package trust.nccgroup.decoderimproved;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

/**
 * Created by j on 12/6/16.
 */

// New modes must inherit from the "ModificationMode" parent class. 
public class EncodeMode extends ModificationMode {
    // ArrayList containing all the different encoders
    private ArrayList<ByteModifier> encoders;

    // EncodeMode Swing components
    private JComboBox<String> encoderComboBox;
    private JPanel comboBoxPanel;

    public EncodeMode() {
		// "super" contains the name that will appear in the mode selection combobox
        super("Encode as...");

        // All encoders are managed within this arraylist, new encoders must be added here to appear
        encoders = new ArrayList<>();
        encoders.add(new PlaintextEncoder());
        encoders.add(new URLEncoder());
        encoders.add(new URLSpecialCharEncoder());
        encoders.add(new HTMLEncoder());
        encoders.add(new HTMLSpecialCharEncoder());
        encoders.add(new Base64Encoder());
        // Add base64 URL safe encoding
        encoders.add(new Base64UrlEncoder());
        encoders.add(new ASCIIHexEncoder());
        encoders.add(new GZIPEncoder());
        encoders.add(new ZlibEncoder());
        //encoders.add(new FooBarEncoder());

        // Swing Components for displaying encoder names
        encoderComboBox = new JComboBox<>();
        encoderComboBox.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        encoderComboBox.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        encoderComboBox.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));

        // Populate the combobox with values
        for (ByteModifier modifier : encoders) {
            encoderComboBox.addItem(modifier.getName());
        }

        // Show all items
        encoderComboBox.setMaximumRowCount(encoders.size());

		// Create a JPanel to contain the JComboBox with all the encode names.
        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        // JPanel does not honor these settings, works based on combobox dimensions
        comboBoxPanel.setMaximumSize(new Dimension(180, 40));
        comboBoxPanel.setMinimumSize(new Dimension(180, 40));
        comboBoxPanel.setPreferredSize(new Dimension(180, 40));
        comboBoxPanel.add(encoderComboBox);

		//"ui" is a JPanel from the ModificationMode parent class that stores the swing UI to draw.
        ui.add(comboBoxPanel);
    }

    private ByteModifier getSelectedMode() {
		// Returns the selected encoder object
        for (ByteModifier modifier : encoders) {
            if (modifier.getName() == encoderComboBox.getSelectedItem()) {
                return modifier;
            }
        }
        // return the first encoder as a default if the mode isn't found (this should never happen)
        return encoders.get(0);
    }

	//modifyByes is called whenever text is updated within Decoder Improved
    public byte[] modifyBytes(byte[] input) throws ModificationException{
		// ModificationException propgates up from modifyBytes called from the ByteModifier exceptions.
		// Get the selected encoder and returns the encoded text.
        return getSelectedMode().modifyBytes(input);
    }
}
