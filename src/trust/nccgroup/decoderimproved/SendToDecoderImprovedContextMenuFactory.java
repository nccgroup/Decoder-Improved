package trust.nccgroup.decoderimproved;

import burp.*;
import trust.nccgroup.decoderimproved.components.MainTab;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by j on 12/9/16.
 */
class SendToDecoderImprovedContextMenuFactory implements IContextMenuFactory {
    private final Color HIGHLIGHT_COLOR = new Color(0xE58900);
    private final Color DEFAULT_COLOR = Color.BLACK;

    private MainTab mainTab;

    SendToDecoderImprovedContextMenuFactory(MainTab _tab) {
        mainTab = _tab;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menu = new ArrayList<>();
        byte ctx = invocation.getInvocationContext();
        ActionListener listener;

        if (ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();
            listener = event -> {
                int start = invocation.getSelectionBounds()[0];
                int end = invocation.getSelectionBounds()[1];
                if (start == end) {
                    mainTab.receiveTextFromMenu(requestResponses[0].getRequest());
                    highlightParentTab();
                } else {
                    mainTab.receiveTextFromMenu(Arrays.copyOfRange(requestResponses[0].getRequest(), start, end));
                    highlightParentTab();
                }
            };
        } else if (ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();
            listener = event -> {
                int start = invocation.getSelectionBounds()[0];
                int end = invocation.getSelectionBounds()[1];
                if (start == end) {
                    mainTab.receiveTextFromMenu(requestResponses[0].getResponse());
                    highlightParentTab();
                } else {
                    mainTab.receiveTextFromMenu(Arrays.copyOfRange(requestResponses[0].getResponse(), start, end));
                    highlightParentTab();
                }
            };
        } else {
            listener = e -> { };
        }

        JMenuItem item = new JMenuItem("Send to Decoder Improved", null);
        item.addActionListener(listener);
        menu.add(item);
        return menu;
    }

    private void highlightParentTab() {
        Component tabComponent = mainTab.getUiComponent();
        if (tabComponent != null) {
            JTabbedPane parentTabbedPane = (JTabbedPane) tabComponent.getParent();
            int index = parentTabbedPane.indexOfComponent(tabComponent);
            parentTabbedPane.setBackgroundAt(index, HIGHLIGHT_COLOR);
            Timer timer = new Timer(3000, e -> {
                parentTabbedPane.setBackgroundAt(index, DEFAULT_COLOR);
            });
            timer.setRepeats(false);
            timer.start();
        }
    }
}
