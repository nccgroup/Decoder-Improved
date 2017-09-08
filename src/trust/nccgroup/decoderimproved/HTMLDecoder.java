package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by j on 1/6/17.
 */

public class HTMLDecoder extends ByteModifier {
    final Pattern HTML_ENCODED_DEC_REGEX = Pattern.compile("&#[0-9]+;");
    final Pattern HTML_ENCODED_HEX_REGEX = Pattern.compile("&#[xX][a-fA-F0-9]+;");
    public HTMLDecoder() {
        super("HTML");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) throws ModificationException{
        StringBuffer output = new StringBuffer();
        StringBuffer output2 = new StringBuffer();

        try {
            CharsetDecoder decoder = Charset.forName("UTF-8").newDecoder();
            decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
            decoder.onMalformedInput(CodingErrorAction.REPORT);
            decoder.decode(ByteBuffer.wrap(input));

            //String displayString = new String(input, "UTF-8");
            String displayString = UTF8StringEncoder.newUTF8String(input);

            Matcher dec_regex_matcher = HTML_ENCODED_DEC_REGEX.matcher(displayString);
            while (dec_regex_matcher.find()) {
                String match_codepoint = dec_regex_matcher.group(0).replaceAll("[^\\d.]", "");
                // System.out.print("Match Codepoint: ");
                // System.out.println(match_codepoint);
                String char_from_codepoint = Character.toString(Character.toChars(Integer.parseInt(match_codepoint))[0]);
                dec_regex_matcher.appendReplacement(output, char_from_codepoint);
            }
            dec_regex_matcher.appendTail(output);

            Matcher hex_regex_matcher = HTML_ENCODED_HEX_REGEX.matcher(output);
            while (hex_regex_matcher.find()) {
                String match_codepoint = hex_regex_matcher.group(0).replaceAll("[^0-9a-fA-F]", "");
                // System.out.print("Match Codepoint: ");
                // System.out.println(match_codepoint);
                String char_from_codepoint = Character.toString(Character.toChars(Integer.parseInt(match_codepoint, 16))[0]);
                hex_regex_matcher.appendReplacement(output2, char_from_codepoint);
            }
            hex_regex_matcher.appendTail(output2);

        } catch (CharacterCodingException e) {
            throw new ModificationException("Invalid input. HTML decoding does not accept strings that contain non-UTF-8 characters.");
        }
        try {
            return output2.toString().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new ModificationException("Invalid output");
        }
    }
}

