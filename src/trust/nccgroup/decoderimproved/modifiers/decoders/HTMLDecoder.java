package trust.nccgroup.decoderimproved.modifiers.decoders;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.jsoup.parser.Parser;
import trust.nccgroup.decoderimproved.modifiers.AbstractByteModifier;
import trust.nccgroup.decoderimproved.Logger;
import trust.nccgroup.decoderimproved.ModificationException;
import trust.nccgroup.decoderimproved.Utils;

/**
 * Created by j on 1/6/17.
 */

public class HTMLDecoder extends AbstractByteModifier {
    private final Pattern HTML_ENTITY_REGEX = Pattern.compile("&([a-zA-Z]+|#([xX][a-fA-F0-9]+|[0-9]+));");

    public HTMLDecoder() {
        super("HTML");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        List<Byte> byteArray = new ArrayList<>(input.length);
        int i = 0;
        int state = 0;
        List<Byte> buf = new ArrayList<>();
        while (i < input.length) {
            byte b = input[i];
            switch (state) {
                case 0: // Seek "&"
                    if (b == '&') {
                        buf.add(b);
                        state = 1;
                    } else {
                        byteArray.add(b);
                    }
                    i++;
                    break;
                case 1: // Seek letter/digit/"#"/";"
                    if (b == '#'
                            || ('A' <= b && b <= 'Z')
                            || ('a' <= b && b <= 'z')
                            || ('0' <= b && b <= '9')
                    ) {
                        buf.add(b);
                        i++;
                    } else if (b == ';') {
                        buf.add(b);
                        try {
                            String encoded = new String(Utils.convertByteArrayListToByteArray(buf));
                            if (HTML_ENTITY_REGEX.matcher(encoded).find()) {
                                String decoded = Parser.unescapeEntities(encoded, false);
                                for (byte decoded_byte : decoded.getBytes()) {
                                    byteArray.add(decoded_byte);
                                }
                            } else {
                                byteArray.addAll(buf);
                            }
                        } catch (Exception e) {
                            byteArray.addAll(buf);
                            Logger.printErrorFromException(e);
                        }
                        buf.clear();
                        state = 0;
                        i++;
                    } else {
                        byteArray.addAll(buf);
                        buf.clear();
                        state = 0;
                    }
                    break;
                default: // Should never reach here
                    throw new ModificationException("Unknown Error");
            }
        }
        byteArray.addAll(buf);
        return Utils.convertByteArrayListToByteArray(byteArray);
    }
}

