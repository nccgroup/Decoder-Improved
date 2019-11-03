package trust.nccgroup.decoderimproved.modes;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;

import com.google.gson.JsonObject;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import trust.nccgroup.decoderimproved.modifiers.AbstractByteModifier;
import trust.nccgroup.decoderimproved.CONSTANTS;
import trust.nccgroup.decoderimproved.Logger;

/**
 * Created by j on 12/8/16.
 */
public class HashMode extends AbstractModificationMode {
    // ArrayList containing all the different encoders
    private ArrayList<AbstractByteModifier> hashAlgorithms;

    // Swing components
    // private JComboBox<String> toBaseComboBox;
    private JComboBox<String> algoComboBox;
    private JPanel comboBoxPanel;
    private String[] algos;

    private JPanel outputSizePanel;

    private JComboBox<String> keccakComboBox;
    private JComboBox<String> sha3ComboBox;
    private JComboBox<String> shakeComboBox;
    private JPanel emptyPanel;

    private CardLayout cardLayout;

    // private JPanel toPanel;
    private JPanel fromPanel;

    public HashMode() {
        super("Hash with...");

        cardLayout = new CardLayout();

        algos = new String[]{"Keccak", "MD2", "MD4", "MD5", "RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320",
                "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3", "SHAKE", "SM3", "Tiger", "GOST3411", "Whirlpool"};
        algoComboBox = new JComboBox<>(algos);

        keccakComboBox = new JComboBox<>(new String[] {"224", "256", "288", "384", "512"});
        sha3ComboBox = new JComboBox<>(new String[] {"224", "256", "384", "512"});
        shakeComboBox = new JComboBox<>(new String[] {"128", "256"});

        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(new Dimension(180, 40));
        comboBoxPanel.setMinimumSize(new Dimension(180, 40));
        comboBoxPanel.setPreferredSize(new Dimension(180, 40));

        algoComboBox.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        algoComboBox.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        algoComboBox.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));

        outputSizePanel = new JPanel(cardLayout);
        outputSizePanel.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        outputSizePanel.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        outputSizePanel.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));

        emptyPanel = new JPanel();
        emptyPanel.setLayout(new BoxLayout(emptyPanel, BoxLayout.PAGE_AXIS));
        emptyPanel.setMaximumSize(new Dimension(180, 40));
        emptyPanel.setMinimumSize(new Dimension(180, 40));
        emptyPanel.setPreferredSize(new Dimension(180, 40));

        outputSizePanel.add(emptyPanel, "emptyPanel");
        outputSizePanel.add(keccakComboBox, "keccakComboBox");
        outputSizePanel.add(sha3ComboBox, "sha3ComboBox");
        outputSizePanel.add(shakeComboBox, "shakeComboBox");
        cardLayout.show(outputSizePanel, "keccakComboBox");

        algoComboBox.addActionListener((ActionEvent e) -> {
            if (algoComboBox.getSelectedItem().equals("Keccak")) {
                cardLayout.show(outputSizePanel, "keccakComboBox");
            } else if (algoComboBox.getSelectedItem().equals("SHA3")) {
                cardLayout.show(outputSizePanel, "sha3ComboBox");
            } else if (algoComboBox.getSelectedItem().equals("SHAKE")) {
                cardLayout.show(outputSizePanel, "shakeComboBox");
            } else {
                cardLayout.show(outputSizePanel, "emptyPanel");
            }
        });

        comboBoxPanel.add(algoComboBox);
        comboBoxPanel.add(outputSizePanel);

        ui.add(comboBoxPanel);
    }

    public byte[] modifyBytes(byte[] input) {
        // Get the selected ByteModifier and use the modifyBytes method from their to update input.
        Digest digest = null;
        byte[] output;

        if (algoComboBox.getSelectedItem().equals("MD2")) {
            digest = new MD2Digest();
        } else if (algoComboBox.getSelectedItem().equals("MD4")) {
            digest = new MD4Digest();
        } else if (algoComboBox.getSelectedItem().equals("MD5")) {
            digest = new MD5Digest();
        } else if (algoComboBox.getSelectedItem().equals("Keccak")) {
            digest = new KeccakDigest(Integer.parseInt((String)keccakComboBox.getSelectedItem()));
        } else if (algoComboBox.getSelectedItem().equals("RIPEMD128")) {
            digest = new RIPEMD128Digest();
        } else if (algoComboBox.getSelectedItem().equals("RIPEMD160")) {
            digest = new RIPEMD160Digest();
        } else if (algoComboBox.getSelectedItem().equals("RIPEMD256")) {
            digest = new RIPEMD256Digest();
        }  else if (algoComboBox.getSelectedItem().equals("RIPEMD320")) {
            digest = new RIPEMD320Digest();
        } else if (algoComboBox.getSelectedItem().equals("SHA1")) {
            digest = new SHA1Digest();
        } else if (algoComboBox.getSelectedItem().equals("SHA224")) {
            digest = new SHA224Digest();
        } else if (algoComboBox.getSelectedItem().equals("SHA256")) {
            digest = new SHA256Digest();
        } else if (algoComboBox.getSelectedItem().equals("SHA384")) {
            digest = new SHA384Digest();
        } else if (algoComboBox.getSelectedItem().equals("SHA512")) {
            digest = new SHA512Digest();
        } else if (algoComboBox.getSelectedItem().equals("SHA3")) {
            digest = new SHA3Digest(Integer.parseInt((String)sha3ComboBox.getSelectedItem()));
        } else if (algoComboBox.getSelectedItem().equals("SHAKE")) {
            digest = new SHAKEDigest(Integer.parseInt((String)shakeComboBox.getSelectedItem()));
        } else if (algoComboBox.getSelectedItem().equals("SM3")) {
            digest = new SM3Digest();
        } else if (algoComboBox.getSelectedItem().equals("Tiger")) {
            digest = new TigerDigest();
        } else if (algoComboBox.getSelectedItem().equals("GOST3411")) {
            digest = new GOST3411Digest();
        } else if (algoComboBox.getSelectedItem().equals("Whirlpool")) {
            digest = new WhirlpoolDigest();
        } else {
            throw new IllegalArgumentException("No such digest");
        }
        output = new byte[digest.getDigestSize()];

        // KeccakDigest	224, 256, 288, 384, 512
        // SHA3Digest	224, 256, 384, 512
        // SHAKEDigest	128, 256

        digest.reset();
        digest.update(input, 0, input.length);
        digest.doFinal(output, 0);
        return output;
    }

    public JsonObject toJSON(){
        JsonObject jsonObject = new JsonObject();
        try {
            String algoName = (String) algoComboBox.getSelectedItem();
            // Add algorithm
            jsonObject.addProperty("a", algoName);
            // Add additional config for specific algorithms
            switch (algoName) {
                case "Keccak":
                    jsonObject.addProperty("c", (String) keccakComboBox.getSelectedItem());
                    break;
                case "SHA3":
                    jsonObject.addProperty("c", (String) sha3ComboBox.getSelectedItem());
                    break;
                case "SHAKE":
                    jsonObject.addProperty("c", (String) shakeComboBox.getSelectedItem());
                    break;
            }
        } catch (Exception e) {
            Logger.printErrorFromException(e);
        }
        return jsonObject;
    }

    public void setFromJSON(JsonObject jsonObject){
        try {
            String algoName = jsonObject.get("a").getAsString();
            algoComboBox.setSelectedItem(algoName);
            switch (algoName) {
                case "Keccak":
                    keccakComboBox.setSelectedItem(jsonObject.get("c").getAsString());
                    break;
                case "SHA3":
                    sha3ComboBox.setSelectedItem(jsonObject.get("c").getAsString());
                    break;
                case "SHAKE":
                    shakeComboBox.setSelectedItem(jsonObject.get("c").getAsString());
                    break;
            }
        } catch (Exception e) {
            Logger.printErrorFromException(e);
        }
    }
}
