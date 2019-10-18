package trust.nccgroup.decoderimproved;

import burp.*;

public class ExtensionRoot implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    MultiDecoderTab multiDecoderTab;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks) {

        callbacks = _callbacks;
        helpers = callbacks.getHelpers();

        Logger.registerExtenderCallbacks(callbacks);

        callbacks.setExtensionName("Decoder Improved");

        multiDecoderTab = new MultiDecoderTab(this);
        //callbacks.customizeUiComponent(multiDecoderTab);
        callbacks.addSuiteTab(multiDecoderTab);
        callbacks.registerContextMenuFactory(new SendToDecoderImprovedContextMenuFactory(multiDecoderTab));

        String savedSettings = callbacks.loadExtensionSetting(multiDecoderTab.getTabCaption());
        // null state will be handled in MultiDecoderTab
        multiDecoderTab.setState(savedSettings, true);

        setSaveFullState();
    }

    public void setSaveFullState() {
        callbacks.getExtensionStateListeners().forEach((x) -> callbacks.removeExtensionStateListener(x));
        callbacks.registerExtensionStateListener(() -> callbacks.saveExtensionSetting(multiDecoderTab.getTabCaption(), multiDecoderTab.getState()));
    }

    public void setClearState() {
        callbacks.getExtensionStateListeners().forEach((x) -> callbacks.removeExtensionStateListener(x));
        callbacks.registerExtensionStateListener(() -> callbacks.saveExtensionSetting(multiDecoderTab.getTabCaption(), null));
    }
}
