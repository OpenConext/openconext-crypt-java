package crypto;


import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class KeyStoreTest {

    @Test
    void encryptAndDecrypt() {
        String privateKeyContent = this.readFile("private_key_pkcs8.pem");
        String publicKeyContent = this.readFile("public_key.pem");

        KeyStore encryptionKeyStore = new RSAKeyStore(publicKeyContent, false);
        KeyStore decryptionKeyStore = new RSAKeyStore(privateKeyContent);
        this.doEncryptAndDecrypt(encryptionKeyStore, decryptionKeyStore);

        assertThrows(IllegalArgumentException.class, () -> decryptionKeyStore.encryptAndEncode("secret"));
        assertThrows(IllegalArgumentException.class, () -> encryptionKeyStore.decodeAndDecrypt("secret"));
    }

    @Test
    void encryptAndDecryptDevMode() {
        KeyStore keyStore = new RSAKeyStore();
        this.doEncryptAndDecrypt(keyStore, keyStore);
    }

    private void doEncryptAndDecrypt(KeyStore encryptionKeyStore, KeyStore decryptionKeyStore) {
        String secret = UUID.randomUUID().toString();
        String encryptedSecret = encryptionKeyStore.encryptAndEncode(secret);
        assertTrue(decryptionKeyStore.isEncryptedSecret(encryptedSecret));

        String decodedSecret = decryptionKeyStore.decodeAndDecrypt(encryptedSecret);
        assertEquals(secret, decodedSecret);
    }

    @SneakyThrows
    private String readFile(String path) {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path);
        return IOUtils.toString(inputStream, Charset.defaultCharset());
    }

}