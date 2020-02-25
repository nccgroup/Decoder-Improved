package trust.nccgroup.decoderimproved.modifiers.decoders;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import trust.nccgroup.decoderimproved.ModificationException;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class Base64DecoderTest {
    private Base64Decoder base64Decoder;

    @BeforeEach
    void setUp() {
        base64Decoder = new Base64Decoder();
    }

    @AfterEach
    void tearDown() {
        base64Decoder = null;
    }

    private static Stream<Arguments> validBase64Provider() {
        return Stream.of(
                Arguments.arguments("talaZZBVNUtJUqUqU+hUlJFfZSuVSpVUqUoB".getBytes(StandardCharsets.UTF_8)
                        , new byte[] {(byte) 0xb5, (byte) 0xa9, (byte) 0x5a, (byte) 0x65, (byte) 0x90, (byte) 0x55
                                , (byte) 0x35, (byte) 0x4b, (byte) 0x49, (byte) 0x52, (byte) 0xa5, (byte) 0x2a
                                , (byte) 0x53, (byte) 0xe8, (byte) 0x54, (byte) 0x94, (byte) 0x91, (byte) 0x5f
                                , (byte) 0x65, (byte) 0x2b, (byte) 0x95, (byte) 0x4a, (byte) 0x95, (byte) 0x54
                                , (byte) 0xa9, (byte) 0x4a, (byte) 0x01}),
                // with one "="
                Arguments.arguments("talaZZBVNUtJUqUqU+hUlJFfZSuVSpVUqQE=".getBytes(StandardCharsets.UTF_8)
                        , new byte[] {(byte)0xb5, (byte)0xa9, (byte)0x5a, (byte)0x65, (byte)0x90, (byte)0x55, (byte)0x35
                                , (byte)0x4b, (byte)0x49, (byte)0x52, (byte)0xa5, (byte)0x2a, (byte)0x53, (byte)0xe8
                                , (byte)0x54, (byte)0x94, (byte)0x91, (byte)0x5f, (byte)0x65, (byte)0x2b, (byte)0x95
                                , (byte)0x4a, (byte)0x95, (byte)0x54, (byte)0xa9, (byte)0x01}),
                // with two "="
                Arguments.arguments("talaZZBVNUtJUqUqU+hUlJFfZSuVSpVUVA==".getBytes(StandardCharsets.UTF_8)
                        , new byte[] {(byte)0xb5, (byte)0xa9, (byte)0x5a, (byte)0x65, (byte)0x90, (byte)0x55
                                , (byte)0x35, (byte)0x4b, (byte)0x49, (byte)0x52, (byte)0xa5, (byte)0x2a, (byte)0x53
                                , (byte)0xe8, (byte)0x54, (byte)0x94, (byte)0x91, (byte)0x5f, (byte)0x65, (byte)0x2b
                                , (byte)0x95, (byte)0x4a, (byte)0x95, (byte)0x54, (byte)0x54}),
                // without padding
                Arguments.arguments("talaZZBVNUtJUqUqU+hUlJFfZSuVSpVUVA".getBytes(StandardCharsets.UTF_8)
                        , new byte[] {(byte)0xb5, (byte)0xa9, (byte)0x5a, (byte)0x65, (byte)0x90, (byte)0x55
                                , (byte)0x35, (byte)0x4b, (byte)0x49, (byte)0x52, (byte)0xa5, (byte)0x2a, (byte)0x53
                                , (byte)0xe8, (byte)0x54, (byte)0x94, (byte)0x91, (byte)0x5f, (byte)0x65, (byte)0x2b
                                , (byte)0x95, (byte)0x4a, (byte)0x95, (byte)0x54, (byte)0x54}),
                // with leading and trailing whitespaces
                Arguments.arguments("\t\n\r  talaZZBVNUtJUqUqU+hUlJFfZSuVSpVUqUoB   \t  ".getBytes(StandardCharsets.UTF_8)
                        , new byte[] {(byte) 0xb5, (byte) 0xa9, (byte) 0x5a, (byte) 0x65, (byte) 0x90, (byte) 0x55
                                , (byte) 0x35, (byte) 0x4b, (byte) 0x49, (byte) 0x52, (byte) 0xa5, (byte) 0x2a
                                , (byte) 0x53, (byte) 0xe8, (byte) 0x54, (byte) 0x94, (byte) 0x91, (byte) 0x5f
                                , (byte) 0x65, (byte) 0x2b, (byte) 0x95, (byte) 0x4a, (byte) 0x95, (byte) 0x54
                                , (byte) 0xa9, (byte) 0x4a, (byte) 0x01})
        );
    }

    private static byte[][] invalidBase64Provider() {
        return new byte[][]{
                // with incomplete padding
                "talaZZBVNUtJUqUqU+hUlJFfZSuVSpVUVA=".getBytes(StandardCharsets.UTF_8),
                // with incorrect padding
                "talaZZBVNUtJUqUqU+hUlJFfZSuVSpVUqQE==".getBytes(StandardCharsets.UTF_8),
                "A=AA".getBytes(StandardCharsets.UTF_8),
                // with incorrect characters in the string
                "AA\nA".getBytes(StandardCharsets.UTF_8),
                "AAA\0".getBytes(StandardCharsets.UTF_8),
                "AAA A".getBytes(StandardCharsets.UTF_8),
        };
    }

    @ParameterizedTest
    @MethodSource("validBase64Provider")
    void testModifyBytes(byte[] input, byte[] expected) throws ModificationException {
        assertArrayEquals(expected, base64Decoder.modifyBytes(input));
    }

    @ParameterizedTest
    @MethodSource("invalidBase64Provider")
    void testModifyBytesThrowsModificationException(byte[] input) {
        assertThrows(ModificationException.class, () -> {
            base64Decoder.modifyBytes(input);
        });
    }
}