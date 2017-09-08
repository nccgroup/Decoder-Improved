package trust.nccgroup.decoderimproved;

import burp.*;

public class ExtensionRoot implements IBurpExtender {

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;

  public void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks) {

    callbacks = _callbacks;
    helpers = callbacks.getHelpers();

    callbacks.setExtensionName("Improved Decoder");

    MultiDecoderTab multiDecoderTab = new MultiDecoderTab(callbacks);
    callbacks.customizeUiComponent(multiDecoderTab);
    callbacks.addSuiteTab(multiDecoderTab);
    callbacks.registerContextMenuFactory(new SendToDecoderImprovedContextMenuFactory(callbacks, multiDecoderTab));
  }
}
