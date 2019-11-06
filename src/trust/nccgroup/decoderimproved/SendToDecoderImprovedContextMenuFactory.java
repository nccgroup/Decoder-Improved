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
        List<JMenuItem> menu = new ArrayList<>();
        byte ctx = invocation.getInvocationContext();
        boolean hasRequest = false;
        boolean hasResponse = false;
        byte[] requestBytes = null;
        byte[] responseBytes = null;

        IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();
        switch (ctx) {
            // Request only
            case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
                requestBytes = requestResponses[0].getRequest();
                hasRequest = true;
                break;
            // Response only
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                responseBytes = requestResponses[0].getResponse();
                hasResponse = true;
                break;
            // Both
            case IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS:
            case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
            case IContextMenuInvocation.CONTEXT_SEARCH_RESULTS:
            case IContextMenuInvocation.CONTEXT_SCANNER_RESULTS:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE:
                requestBytes = requestResponses[0].getRequest();
                responseBytes = requestResponses[0].getResponse();
                hasRequest = true;
                hasResponse = true;
                break;
            default: // should never reach here
                Logger.printError("Unknown invocation context: " + ctx);
                return null;
        }

        // Request or response only
        if (hasRequest ^ hasResponse) {
            byte[] finalTextBytes = hasRequest ? requestBytes : responseBytes;
            JMenuItem menuItem = new JMenuItem("Send to Decoder Improved");
            menuItem.addActionListener((e) -> {
                int start = invocation.getSelectionBounds()[0];
                int end = invocation.getSelectionBounds()[1];
                if (start == end) {
                    mainTab.receiveTextFromMenu(finalTextBytes);
                    highlightParentTab();
                } else {
                    mainTab.receiveTextFromMenu(Arrays.copyOfRange(finalTextBytes, start, end));
                    highlightParentTab();
                }
            });
            menu.add(menuItem);
        } else { // Both (from the switch above there's no case that both are false)
            JMenu subMenu = new JMenu("Send to Decoder Improved");
            if (requestBytes != null && requestBytes.length > 0) {
                Logger.printOutput("Req");
                byte[] finalRequestTextBytes = requestBytes;
                JMenuItem requestMenuItem = new JMenuItem("Request");
                requestMenuItem.addActionListener((e) -> {
                    mainTab.receiveTextFromMenu(finalRequestTextBytes);
                    highlightParentTab();
                });
                subMenu.add(requestMenuItem);
            }
            if (responseBytes != null && responseBytes.length > 0) {
                Logger.printOutput("Resp");
                byte[] finalResponseTextBytes = responseBytes;
                JMenuItem responseMenuItem = new JMenuItem("Response");
                responseMenuItem.addActionListener((e) -> {
                    mainTab.receiveTextFromMenu(finalResponseTextBytes);
                    highlightParentTab();
                });
                subMenu.add(responseMenuItem);
            }
            if (subMenu.getItemCount() > 0) {
                menu.add(subMenu);
            }
        }
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
