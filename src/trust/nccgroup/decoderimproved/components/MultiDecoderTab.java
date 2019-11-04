package trust.nccgroup.decoderimproved.components;

import burp.ITab;
import com.google.gson.*;
import trust.nccgroup.decoderimproved.ExtensionRoot;
import trust.nccgroup.decoderimproved.Logger;
import trust.nccgroup.decoderimproved.modes.AbstractModificationMode;
import trust.nccgroup.decoderimproved.modifiers.encoders.PlaintextEncoder;
import trust.nccgroup.decoderimproved.modes.EncodeMode;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import java.util.Base64;

public class MultiDecoderTab extends JPanel implements ITab {

    private JTabbedPane main;
    private JPanel newTabButton;

    private ConfigPanel configPanel;

    private boolean tabChangeListenerLock = false;

    //Plugin starts with one decoder tab open and the "new tab" tab
    private int overallCount = 0;

    public boolean isTabChangeListenerLock() {
        return tabChangeListenerLock;
    }

    void setTabChangeListenerLock(boolean tabChangeListenerLock) {
        this.tabChangeListenerLock = tabChangeListenerLock;
    }

    public MultiDecoderTab(ExtensionRoot extensionRoot) {
        // Set main tab layout
        setLayout(new BorderLayout());
        //initialize ui elements
        main = new JTabbedPane();

        // Add "new tab" tab
        newTabButton = new JPanel();
        newTabButton.setName("...");
        main.add(newTabButton);

        main.addChangeListener((ChangeEvent e) -> {
            // If the '...' button is pressed, add a new tab
            if (!tabChangeListenerLock) {
                if (main.getSelectedIndex() == main.getTabCount() - 1) {
                    addTab();
                } else {
                    DecoderTab dt = (DecoderTab) main.getSelectedComponent();
                    dt.getDecoderSegments().get(0).getTextEditor().requestFocus();
                }
            }
            for (int i = 0; i < main.getTabCount() - 2; i++) {
                DecoderTab.DecoderTabHandle dth = (DecoderTab.DecoderTabHandle) main.getTabComponentAt(i);
                dth.tabName.setEditable(false);
            }
        });
        add(main, BorderLayout.CENTER);

        configPanel = new ConfigPanel(extensionRoot);
        add(configPanel, BorderLayout.SOUTH);
    }

    // Logic for adding new tabs
    void addTab() {
        tabChangeListenerLock = true;
        // Add a new tab
        overallCount += 1;
        DecoderTab mt2 = new DecoderTab(Integer.toString(overallCount, 10), this);
        main.add(mt2);
        main.setTabComponentAt(main.indexOfComponent(mt2), mt2.getTabHandleElement());
        main.setSelectedComponent(mt2);
        //mt2.getDecoderSegments().get(0).getTextEditor().requestFocus();

        // This moves the '...' tab to the end of the tab list
        main.remove(newTabButton);
        main.add(newTabButton);

        tabChangeListenerLock = false;
    }

    private int firstEmptyDecoder() {
        if (main.getComponentAt(main.getTabCount() - 2) instanceof DecoderTab) {
            DecoderTab dt = (DecoderTab) main.getComponentAt(main.getTabCount() - 2);
            if (dt.getDecoderSegments().get(0).dsState.getByteSize() == 0) {
                return main.getTabCount() - 2;
            }
        }
        return -1;
    }

    public void receiveTextFromMenu(byte[] selectedTextBytes) {
        // TODO: Add checks to see if the decoder segment is populated.
        if (firstEmptyDecoder() == -1) {
            // Add a new tab
            addTab();
            DecoderTab dt = (DecoderTab) main.getComponentAt(main.getTabCount() - 2);
            dt.getDecoderSegments().get(0).dsState.setByteArrayList(selectedTextBytes);
            dt.updateDecoderSegments(0);
            for (DecoderSegment ds : dt.getDecoderSegments()) {
                ds.updateEditors(dt.getDecoderSegments().get(0).dsState);
            }
        } else {
            DecoderTab dt = (DecoderTab) main.getComponentAt(firstEmptyDecoder());
            dt.getDecoderSegments().get(0).dsState.setByteArrayList(selectedTextBytes);
            dt.updateDecoderSegments(0);
            for (DecoderSegment ds : dt.getDecoderSegments()) {
                ds.updateEditors(dt.getDecoderSegments().get(0).dsState);
            }
        }
    }

    @Override
    public String getTabCaption() {
        return "Decoder Improved";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    JTabbedPane getMain() {
        return main;
    }

    // Save the current state of extension to a JsonObject string
    public String getState() {
        JsonObject extensionStateObject = new JsonObject();
        JsonArray tabStateArray = new JsonArray();
        // Save all tabs except the last "..." one
        for (int i = 0; i < main.getTabCount() - 1; i++) {
            JsonObject tabStateObject = new JsonObject();
            DecoderTab.DecoderTabHandle tabHandle = (DecoderTab.DecoderTabHandle) main.getTabComponentAt(i);
            // Tab name
            tabStateObject.addProperty("n", tabHandle.tabName.getText());
            // Bytes in first segment of each tab
            tabStateObject.addProperty("b", Base64.getEncoder().encodeToString(tabHandle.decoderTab.getDecoderSegments().get(0).dsState.getByteArray()));
            // Save panel states of all segments
            JsonArray segmentStateArray = new JsonArray();
            for (DecoderSegment decoderSegment : tabHandle.decoderTab.getDecoderSegments()) {
                JsonObject segmentStateObject = new JsonObject();
                // Whether hex editor is selected
                segmentStateObject.addProperty("h", decoderSegment.hexRadio.isSelected());
                AbstractModificationMode mode = decoderSegment.modes.getSelectedMode();
                // Mode name
                segmentStateObject.addProperty("m", mode.getName());
                // Mode configurations
                segmentStateObject.add("c", mode.toJSON());
                // Add each segment state object to the segment state array
                segmentStateArray.add(segmentStateObject);
            }
            // Save the segment state array in tab state object
            tabStateObject.add("s", segmentStateArray);
            // Add each tab state object to the tab state array
            tabStateArray.add(tabStateObject);
        }
        extensionStateObject.addProperty("i", main.getSelectedIndex());
        extensionStateObject.add("t", tabStateArray);
        return extensionStateObject.toString();
    }

    // Decode the saved extension setting string and recover all tabs
    public void setState(String stateString, boolean initial) {
        if (stateString == null || stateString.isEmpty()) {
            if (initial) {
                addTab();
                main.setSelectedIndex(0);
                return;
            } else {
                throw new IllegalArgumentException("Error reading file or file is empty");
            }
        }
        try {
            int originalIndex = initial ? 0 : main.getSelectedIndex();
            int originalTabCount = main.getTabCount();
            JsonObject extensionStateObject = JsonParser.parseString(stateString).getAsJsonObject();
            JsonArray tabStateArray = extensionStateObject.get("t").getAsJsonArray();
            if (tabStateArray.size() == 0) {
                if (initial) {
                    addTab();
                    main.setSelectedIndex(0);
                }
                return;
            }
            for (int i = 0; i < tabStateArray.size(); i++) {
                JsonObject tabStateObject = tabStateArray.get(i).getAsJsonObject();
                // Build a new tab for each tab object
                addTab();
                DecoderTab dt = (DecoderTab) main.getComponentAt(originalTabCount + i - 1);
                dt.decoderTabHandle.tabName.setText(tabStateObject.get("n").getAsString());
                DecoderSegment.DecoderSegmentState dsState = dt.getDecoderSegments().get(0).dsState;
                dsState.setByteArrayList(Base64.getDecoder().decode(tabStateObject.get("b").getAsString()));
                JsonArray segmentStateArray = tabStateObject.getAsJsonArray("s");
                // Create (n - 1) new segments and update state for the 1..n-1 segments
                for (int j = 0; j < segmentStateArray.size() - 1; j++) {
                    dt.decoderSegments.get(j).addDecoderSegment();
                }
                // Update state for all segments
                for (int j = 0; j < dt.decoderSegments.size(); j++) {
                    dt.decoderSegments.get(j).updateEditors(dsState);
                }
                for (int j = 0; j < segmentStateArray.size(); j++) {
                    JsonObject segmentStateObject = segmentStateArray.get(j).getAsJsonObject();
                    DecoderSegment ds = dt.decoderSegments.get(j);
                    String modeName = segmentStateObject.get("m").getAsString();
                    JsonObject config = segmentStateObject.get("c").getAsJsonObject();
                    // If encoded as plain, do not "select" the item as it will create a new segment under the last one
                    if (!(modeName.equals(EncodeMode.NAME) && config.get("e").getAsString().equals(PlaintextEncoder.NAME))) {
                        ds.modes.setSelectedMode(modeName);
                        ds.modes.getSelectedMode().setFromJSON(config);
                    }
                    // Editor must be set at last to "force" the selection
                    if (segmentStateObject.get("h").getAsBoolean()) {
                        ds.displayHexEditor();
                    } else {
                        ds.displayTextEditor();
                    }
                }
            }
            main.setSelectedIndex(initial ? extensionStateObject.get("i").getAsInt() : originalIndex);
        } catch (Exception e) {
            if (initial) {
                addTab();
                main.setSelectedIndex(0);
                Logger.printErrorFromException(e);
            } else {
                throw e;
            }
        }
    }
}