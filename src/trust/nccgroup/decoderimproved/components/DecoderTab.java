package trust.nccgroup.decoderimproved.components;

import trust.nccgroup.decoderimproved.ModificationException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class DecoderTab extends JPanel {
    DecoderTabHandle decoderTabHandle;
    JPanel decoderTabBody;
    ArrayList<DecoderSegment> decoderSegments;

    private JScrollPane scrollingBodyHolder;

    DecoderTab(String _title, MainTab _parent) {
        decoderTabHandle = new DecoderTabHandle(_title, _parent, this);
        setupComponents();
    }

    private void clear() {
        decoderSegments.forEach(x -> {
            x.dsState.clear();
        });
        decoderSegments.clear();
    }

    Component getTabHandleElement() {
        return decoderTabHandle;
    }

    ArrayList<DecoderSegment> getDecoderSegments() {
        return new ArrayList<>(decoderSegments);
    }

    private void setupComponents() {
        scrollingBodyHolder = new JScrollPane();
        decoderTabBody = new JPanel();
        decoderSegments = new ArrayList<>();
        decoderSegments.add(new DecoderSegment(this));
        this.setLayout(new BorderLayout());
        decoderTabBody.setLayout(new BoxLayout(decoderTabBody, BoxLayout.PAGE_AXIS));

        for (DecoderSegment decoderSegment : decoderSegments) {
            decoderTabBody.add(decoderSegment);
        }

        scrollingBodyHolder.setViewportView(decoderTabBody);
        this.add(scrollingBodyHolder, BorderLayout.CENTER);
    }

    void addDecoderSegment() {
        DecoderSegment ds = new DecoderSegment(this);
        decoderTabBody.add(Box.createRigidArea(new Dimension(0, 10)));
        decoderSegments.add(ds);
        decoderTabBody.add(ds);

        // Update last segment (based on second last segment)
        updateNextDecoderSegment(decoderSegments.size() - 2);
    }

    void updateDecoderSegments(int activeDecoderSegmentIndex, boolean addSegment) {
        if (addSegment && activeDecoderSegmentIndex == decoderSegments.size() - 1) {
            addDecoderSegment();
        }
        // This goes through the entire list of decoder segments and updates all the ones
        // past the current one.
        for (int i = activeDecoderSegmentIndex; i < decoderSegments.size(); i++) {
            updateNextDecoderSegment(i);
        }
    }

    private void updateNextDecoderSegment(int activeDecoderSegmentIndex) {
        // If the item is at the end of the list there isn't anything to update
        // i.e. this prevents an array out of bounds error
        if (activeDecoderSegmentIndex >= decoderSegments.size() - 1) {
            return;
        }

        // Get the active segment
        DecoderSegment activeDecoderSegment = decoderSegments.get(activeDecoderSegmentIndex);

        // This gets the next decoder segment
        DecoderSegment nextDecoderSegment = decoderSegments.get(activeDecoderSegmentIndex + 1);

        // Check to see if there was an error in the active decoder segment
        // If there was an error in a previous decoder segment propagate that to all following segments
        // Then change the text editor background red and display the error message
        if (activeDecoderSegment.hasError) {
            nextDecoderSegment.hasError = true;
            nextDecoderSegment.showError(activeDecoderSegment.errorMessage);
            return;
        }

        //This code does all the byte modification
        try {
            nextDecoderSegment.dsState.setByteArrayList(activeDecoderSegment.modeManager.modifyBytes(activeDecoderSegment.dsState.getByteArray()));
            nextDecoderSegment.updateEditors(nextDecoderSegment.dsState);
            nextDecoderSegment.hasError = false;
            try {
                CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
                decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
                decoder.onMalformedInput(CodingErrorAction.REPORT);
                decoder.decode(ByteBuffer.wrap(nextDecoderSegment.dsState.getByteArray()));
                // new String(nextDecoderSegment.dsState.getByteArray(), StandardCharsets.UTF_8);
                // new UTF.newUTF8String(nextDecoderSegment.dsState.getByteArray());
                nextDecoderSegment.displayTextEditor();
            } catch (Exception e) {
                nextDecoderSegment.displayHexEditor();
            }
        } catch (ModificationException e) {
            nextDecoderSegment.showError(e.getMessage());
        }
    }

    static class DecoderTabHandle extends JPanel {
        private JTabbedPane parentTabbedPane;
        DecoderTab decoderTab;
        JTextField tabName;

        private DecoderTabHandle(String title, MainTab mainTab, DecoderTab decoderTab) {
            this.decoderTab = decoderTab;
            this.parentTabbedPane = mainTab.getTabbedPane();
            this.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));
            this.setOpaque(false);
            JLabel label = new JLabel(title);
            label.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
            tabName = new JTextField(title);
            tabName.setOpaque(false);
            tabName.setBorder(null);
            tabName.setBackground(new Color(0, 0, 0, 0));
            tabName.setEditable(false);
            tabName.setCaretColor(Color.BLACK);

            this.add(tabName);
            JButton closeButton = new JButton("✕");
            closeButton.setFont(new Font("monospaced", Font.PLAIN, 10));
            closeButton.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
            closeButton.setForeground(Color.GRAY);

            closeButton.setBorderPainted(false);
            closeButton.setContentAreaFilled(false);
            closeButton.setOpaque(false);

            tabName.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (!parentTabbedPane.getSelectedComponent().equals(decoderTab)) {
                        parentTabbedPane.setSelectedComponent(decoderTab);
                        for (int i = 0; i < parentTabbedPane.getTabCount()-1; i++) {
                            if (!parentTabbedPane.getComponentAt(i).equals(decoderTab)) {
                                DecoderTabHandle dth = (DecoderTabHandle) parentTabbedPane.getTabComponentAt(i);
                                dth.tabName.setEditable(false);
                            }
                        }
                    } else {
                        tabName.setEditable(true);
                    }
                }

                @Override
                public void mouseClicked(MouseEvent e) {
                    if (!parentTabbedPane.getSelectedComponent().equals(decoderTab)) {
                        parentTabbedPane.setSelectedComponent(decoderTab);
                        for (int i = 0; i < parentTabbedPane.getTabCount()-1; i++) {
                            if (!parentTabbedPane.getComponentAt(i).equals(decoderTab)) {
                                DecoderTabHandle dth = (DecoderTabHandle) parentTabbedPane.getTabComponentAt(i);
                                dth.tabName.setEditable(false);
                            }
                        }
                    } else {
                        tabName.setEditable(true);
                    }
                }
            });

            closeButton.addActionListener(e -> {
                mainTab.setTabChangeListenerLock(true);
                if (parentTabbedPane.getSelectedComponent().equals(decoderTab)) {
                    if (parentTabbedPane.getTabCount() == 2) {
                        parentTabbedPane.remove(decoderTab);
                        //autoRepeaters.remove(autoRepeater);
                        mainTab.addTab();
                        mainTab.setTabChangeListenerLock(true);
                    } else if (parentTabbedPane.getTabCount() > 2) {
                        parentTabbedPane.remove(decoderTab);
                        //autoRepeaters.remove(autoRepeater);
                    }
                    decoderTab.clear();
                    if (parentTabbedPane.getSelectedIndex() == parentTabbedPane.getTabCount() - 1) {
                        parentTabbedPane.setSelectedIndex(parentTabbedPane.getTabCount() - 2);
                    }
                } else {
                    parentTabbedPane.setSelectedComponent(decoderTab);
                }
                mainTab.setTabChangeListenerLock(false);
            });

            this.add(closeButton);
        }
    }
}
