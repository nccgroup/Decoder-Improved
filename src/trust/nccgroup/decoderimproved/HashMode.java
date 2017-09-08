package trust.nccgroup.decoderimproved;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;

/**
 * Created by j on 12/8/16.
 */
public class HashMode extends ModificationMode {
    // ArrayList containing all the different encoders
    private ArrayList<ByteModifier> hashAlgorithms;

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
                "SHA1", "SHA224", "SHA256", "SHA384", "SHA3", "SHAKE", "SM3", "Tiger", "GOST3411"};
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

    public byte[] modifyBytes(byte[] input) throws ModificationException{
        // Get the selected ByteModifier and use the modifyBytes method from their to update input.
        Digest digest;
        byte[] output;

        if (algoComboBox.getSelectedItem().equals("MD2")) {
            digest = new MD2Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("MD4")) {
            digest = new MD4Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("MD5")) {
            digest = new MD5Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("Keccak")) {
            digest = new KeccakDigest(Integer.parseInt((String)keccakComboBox.getSelectedItem()));
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("RIPEMD128")) {
            digest = new RIPEMD128Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("RIPEMD160")) {
            digest = new RIPEMD160Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("RIPEMD256")) {
            digest = new RIPEMD256Digest();
            output = new byte[digest.getDigestSize()];
        }  else if (algoComboBox.getSelectedItem().equals("RIPEMD320")) {
            digest = new RIPEMD320Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("SHA1")) {
            digest = new SHA1Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("SHA224")) {
            digest = new SHA224Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("SHA256")) {
            digest = new SHA256Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("SHA384")) {
            digest = new SHA384Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("SHA3")) {
            digest = new SHA3Digest(Integer.parseInt((String)sha3ComboBox.getSelectedItem()));
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("SHAKE")) {
            digest = new SHAKEDigest(Integer.parseInt((String)shakeComboBox.getSelectedItem()));
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("SM3")) {
            digest = new SM3Digest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("Tiger")) {
            digest = new TigerDigest();
            output = new byte[digest.getDigestSize()];
        } else if (algoComboBox.getSelectedItem().equals("GOST3411")) {
            digest = new GOST3411Digest();
            output = new byte[digest.getDigestSize()];
        } else {
            digest = new WhirlpoolDigest();
            output = new byte[digest.getDigestSize()];
        }

        // KeccakDigest	224, 256, 288, 384, 512
        // SHA3Digest	224, 256, 384, 512
        // SHAKEDigest	128, 256

        digest.reset();
        digest.update(input, 0, input.length);
        digest.doFinal(output, 0);
        return output;
    }
}
