package burp;

import trust.nccgroup.decoderimproved.ExtensionRoot;

@SuppressWarnings("unused")
public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        ExtensionRoot exr = new ExtensionRoot(callbacks);
    }
}
