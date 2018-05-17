package trust.nccgroup.decoderimproved;

import javax.xml.XMLConstants;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class XmlPrettifier extends ByteModifier {
    public XmlPrettifier() {
        super("XML");
    }

    @Override
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        // @See https://stackoverflow.com/a/1264912
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(input);
            Source xmlInput = new StreamSource(bais);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            StreamResult xmlOutput = new StreamResult(baos);
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(xmlInput, xmlOutput);
            return baos.toByteArray();
        } catch (TransformerException e) {
            throw new ModificationException("Invalid XML");
        }
    }
}
