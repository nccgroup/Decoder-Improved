package trust.nccgroup.decoderimproved.components;

import burp.ITab;
import com.google.gson.*;
import trust.nccgroup.decoderimproved.CONSTANTS;
import trust.nccgroup.decoderimproved.ExtensionRoot;
import trust.nccgroup.decoderimproved.Logger;
import trust.nccgroup.decoderimproved.modes.AbstractModificationMode;
import trust.nccgroup.decoderimproved.modifiers.encoders.PlaintextEncoder;
import trust.nccgroup.decoderimproved.modes.EncodeMode;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;

public class MainTab extends JPanel implements ITab {

    private JTabbedPane tabbedPane;
    private JPanel newTabButton;
    private DecoderTab lastClosedDecoderTab = null;

    private ConfigPanel configPanel;

    private boolean tabChangeListenerLock = false;
    private JPopupMenu tabMenu;

    private int overallCount = 0;
    private List<Integer> loadedTabNameIntList = new ArrayList<>();

    public boolean isTabChangeListenerLock() {
        return tabChangeListenerLock;
    }

    void setTabChangeListenerLock(boolean tabChangeListenerLock) {
        this.tabChangeListenerLock = tabChangeListenerLock;
    }

    public MainTab(ExtensionRoot extensionRoot) {
        // Set main tab layout
        setLayout(new BorderLayout());
        //initialize ui elements
        tabbedPane = new JTabbedPane();

        // Add "new tab" tab
        newTabButton = new JPanel();
        newTabButton.setName("...");
        tabbedPane.add(newTabButton);

        tabbedPane.addChangeListener((ChangeEvent e) -> {
            // If the '...' button is pressed, add a new tab
            if (!tabChangeListenerLock) {
                if (tabbedPane.getSelectedIndex() == tabbedPane.getTabCount() - 1) {
                    addTab();
                } else {
                    DecoderTab dt = (DecoderTab) tabbedPane.getSelectedComponent();
                    dt.getDecoderSegments().get(0).getTextEditor().requestFocus();
                }
            }
        });
        tabbedPane.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    tabMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        add(tabbedPane, BorderLayout.CENTER);

        configPanel = new ConfigPanel(extensionRoot);
        add(configPanel, BorderLayout.SOUTH);

        tabMenu = new TabMenu();

        // Register hotkeys under the main tab
        // Ctrl + w to close the current tab
        getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(KeyEvent.VK_W, CONSTANTS.META_MASK, true), "close_tab");
        getActionMap().put("close_tab", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                closeTab((DecoderTab)tabbedPane.getSelectedComponent());
            }
        });
        // Ctrl + t to create a new tab
        getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(KeyEvent.VK_T, CONSTANTS.META_MASK, true), "new_tab");
        getActionMap().put("new_tab", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addTab();
            }
        });
        // Ctrl + shift + t to reopen the last closed tab
        getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(KeyEvent.VK_T, CONSTANTS.META_MASK | InputEvent.SHIFT_DOWN_MASK, true), "reopen_tab");
        getActionMap().put("reopen_tab", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                reopenLastTab();
            }
        });
    }

    // Add an unnamed tab
    private void addTab() {
        do {
            overallCount += 1;
        } while (loadedTabNameIntList.contains(overallCount));
        addTab(Integer.toString(overallCount, 10));
    }

    // Logic for adding new tabs
    private void addTab(String tabName) {
        tabChangeListenerLock = true;
        // Add a new tab
        DecoderTab newDecoderTab = new DecoderTab(tabName, this);
        tabbedPane.add(newDecoderTab, tabbedPane.getTabCount() - 1);
        tabbedPane.setTabComponentAt(tabbedPane.indexOfComponent(newDecoderTab), newDecoderTab.getTabHandleElement());
        tabbedPane.setSelectedComponent(newDecoderTab);
        newDecoderTab.getDecoderSegments().get(0).getTextEditor().requestFocus();
        tabChangeListenerLock = false;
    }

    private void addTab(DecoderTab tab) {
        tabChangeListenerLock = true;
        tabbedPane.add(tab, tabbedPane.getTabCount() - 1);
        tabbedPane.setTabComponentAt(tabbedPane.indexOfComponent(tab), tab.getTabHandleElement());
        tabbedPane.setSelectedComponent(tab);
        tab.getDecoderSegments().get(0).getTextEditor().requestFocus();
        tabChangeListenerLock = false;
    }

    void closeTab(DecoderTab decoderTab) {
        tabChangeListenerLock = true;
        if (tabbedPane.getSelectedComponent().equals(decoderTab)) {
            if (tabbedPane.getTabCount() == 2) {
                tabbedPane.remove(decoderTab);
                addTab();
                tabChangeListenerLock = true;
            } else if (tabbedPane.getTabCount() > 2) {
                tabbedPane.remove(decoderTab);
            }
            // Update last closed tab
            if (lastClosedDecoderTab != null) {
                lastClosedDecoderTab.clear();
            }
            lastClosedDecoderTab = decoderTab;
            if (tabbedPane.getSelectedIndex() == tabbedPane.getTabCount() - 1) {
                tabbedPane.setSelectedIndex(tabbedPane.getTabCount() - 2);
            }
        } else {
            tabbedPane.setSelectedComponent(decoderTab);
        }
        tabChangeListenerLock = false;
    }

    private void reopenLastTab() {
        if (lastClosedDecoderTab != null) {
            addTab(lastClosedDecoderTab);
            lastClosedDecoderTab = null;
        }
    }

    private int firstEmptyDecoder() {
        if (tabbedPane.getComponentAt(tabbedPane.getTabCount() - 2) instanceof DecoderTab) {
            DecoderTab dt = (DecoderTab) tabbedPane.getComponentAt(tabbedPane.getTabCount() - 2);
            if (dt.getDecoderSegments().get(0).dsState.getByteSize() == 0) {
                return tabbedPane.getTabCount() - 2;
            }
        }
        return -1;
    }

    public void receiveTextFromMenu(byte[] selectedTextBytes) {
        if (selectedTextBytes == null || selectedTextBytes.length == 0) {
            return;
        }
        // TODO: Add checks to see if the decoder segment is populated.
        if (firstEmptyDecoder() == -1) {
            // Add a new tab
            addTab();
            DecoderTab dt = (DecoderTab) tabbedPane.getComponentAt(tabbedPane.getTabCount() - 2);
            dt.getDecoderSegments().get(0).dsState.setByteArrayList(selectedTextBytes);
            dt.updateDecoderSegments(0, false);
            for (DecoderSegment ds : dt.getDecoderSegments()) {
                ds.updateEditors(dt.getDecoderSegments().get(0).dsState);
            }
        } else {
            DecoderTab dt = (DecoderTab) tabbedPane.getComponentAt(firstEmptyDecoder());
            dt.getDecoderSegments().get(0).dsState.setByteArrayList(selectedTextBytes);
            dt.updateDecoderSegments(0, false);
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

    JTabbedPane getTabbedPane() {
        return tabbedPane;
    }

    // Save the current state of extension to a JsonObject string
    public String getState() {
        JsonObject extensionStateObject = new JsonObject();
        JsonArray tabStateArray = new JsonArray();
        // Save all tabs except the last "..." one
        for (int i = 0; i < tabbedPane.getTabCount() - 1; i++) {
            JsonObject tabStateObject = new JsonObject();
            DecoderTab.DecoderTabHandle tabHandle = (DecoderTab.DecoderTabHandle) tabbedPane.getTabComponentAt(i);
            // Tab name
            tabStateObject.addProperty("n", tabHandle.tabNameField.getText());
            // Bytes in first segment of each tab
            tabStateObject.addProperty("b", Base64.getEncoder().encodeToString(tabHandle.decoderTab.getDecoderSegments().get(0).dsState.getByteArray()));
            // Save panel states of all segments
            JsonArray segmentStateArray = new JsonArray();
            for (DecoderSegment decoderSegment : tabHandle.decoderTab.getDecoderSegments()) {
                JsonObject segmentStateObject = new JsonObject();
                // Whether hex editor is selected
                segmentStateObject.addProperty("h", decoderSegment.hexRadio.isSelected());
                AbstractModificationMode mode = decoderSegment.modeManager.getSelectedMode();
                // Mode name
                segmentStateObject.addProperty("m", mode.getModeName());
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
        extensionStateObject.addProperty("i", tabbedPane.getSelectedIndex());
        extensionStateObject.add("t", tabStateArray);
        return extensionStateObject.toString();
    }

    // Decode the saved extension setting string and recover all tabs
    public void setState(String stateString, boolean initial) {
        if (stateString == null || stateString.isEmpty()) {
            if (initial) {
                addTab();
                tabbedPane.setSelectedIndex(0);
                return;
            } else {
                throw new IllegalArgumentException("Error reading file or file is empty");
            }
        }
        try {
            int originalIndex = initial ? 0 : tabbedPane.getSelectedIndex();
            int originalTabCount = tabbedPane.getTabCount();
            JsonObject extensionStateObject = JsonParser.parseString(stateString).getAsJsonObject();
            JsonArray tabStateArray = extensionStateObject.get("t").getAsJsonArray();
            if (tabStateArray.size() == 0) {
                if (initial) {
                    addTab();
                    tabbedPane.setSelectedIndex(0);
                }
                return;
            }
            for (int i = 0; i < tabStateArray.size(); i++) {
                JsonObject tabStateObject = tabStateArray.get(i).getAsJsonObject();
                // Build a new tab for each tab object
                String tabName = tabStateObject.get("n").getAsString();
                addTab(tabName);
                // If a tab is loaded from config and contains numeric name, add its name to the "blacklist" of tab names
                try {
                    int tabNameInt = Integer.parseInt(tabName);
                    if (tabNameInt > 0) {
                        loadedTabNameIntList.add(tabNameInt);
                    }
                } catch (NumberFormatException ignored) {
                }
                DecoderTab dt = (DecoderTab) tabbedPane.getComponentAt(originalTabCount + i - 1);
                DecoderSegment.DecoderSegmentState dsState = dt.getDecoderSegments().get(0).dsState;
                dsState.setByteArrayList(Base64.getDecoder().decode(tabStateObject.get("b").getAsString()));
                JsonArray segmentStateArray = tabStateObject.getAsJsonArray("s");
                // Create (n - 1) new segments and update state for the 1..n-1 segments
                for (int j = 0; j < segmentStateArray.size() - 1; j++) {
                    dt.addDecoderSegment();
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
                        ds.modeManager.setSelectedMode(modeName);
                        ds.modeManager.getSelectedMode().setFromJSON(config);
                    }
                    // Editor must be set at last to "force" the selection
                    if (segmentStateObject.get("h").getAsBoolean()) {
                        ds.displayHexEditor();
                    } else {
                        ds.displayTextEditor();
                    }
                }
            }
            tabbedPane.setSelectedIndex(initial ? extensionStateObject.get("i").getAsInt() : originalIndex);
        } catch (Exception e) {
            if (initial) {
                addTab();
                tabbedPane.setSelectedIndex(0);
                Logger.printErrorFromException(e);
            } else {
                throw e;
            }
        }
    }

    private class TabMenu extends JPopupMenu {
        //JMenuItem closeTabItem;
        JMenuItem reopenClosedTabItem;
        TabMenu() {
            //closeTabItem = new JMenuItem("Close tab");
            reopenClosedTabItem = new JMenuItem("Reopen closed tab");
            //add(closeTabItem);
            add(reopenClosedTabItem);

            /*
            closeTabItem.addActionListener((e) -> {
                try {
                    closeTab((DecoderTab) tabbedPane.getSelectedComponent());
                } catch (Exception ee) {
                    Logger.printErrorFromException(ee);
                }
            });*/
            reopenClosedTabItem.addActionListener((e) -> {
                reopenLastTab();
            });

            addPopupMenuListener(new PopupMenuListener() {
                @Override
                public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                    reopenClosedTabItem.setEnabled(lastClosedDecoderTab != null);
                }

                @Override
                public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {

                }

                @Override
                public void popupMenuCanceled(PopupMenuEvent e) {

                }
            });
        }
    }
}