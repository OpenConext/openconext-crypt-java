package crypto;

import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

abstract class AbstractKeyStoreTest {

    abstract KeyStore encryptionKeyStore(String publicKeyContent);

    abstract KeyStore decryptionKeyStore(String privateKeyContent);

    @Test
    void encryptAndDecrypt() {
        String privateKeyContent = this.readFile("private_key_pkcs8.pem");
        String publicKeyContent = this.readFile("public_key.pem");

        KeyStore encryptionKeyStore = encryptionKeyStore(publicKeyContent);
        KeyStore decryptionKeyStore = decryptionKeyStore(privateKeyContent);

        this.doEncryptAndDecrypt(encryptionKeyStore, decryptionKeyStore);

        assertThrows(IllegalArgumentException.class, () -> decryptionKeyStore.encryptAndEncode("secret"));
        assertThrows(IllegalArgumentException.class, () -> encryptionKeyStore.decodeAndDecrypt("secret"));
    }

    @Test
    void encryptAndDecryptDevMode() {
        KeyStore keyStore = new HybridRSAKeyStore();
        this.doEncryptAndDecrypt(keyStore, keyStore);
    }

    private void doEncryptAndDecrypt(KeyStore encryptionKeyStore, KeyStore decryptionKeyStore) {
        String secret = UUID.randomUUID().toString();
        String encryptedSecret = encryptionKeyStore.encryptAndEncode(secret);
        String encryptedSecretDuplicate = encryptionKeyStore.encryptAndEncode(secret);
        //Rainbow attacks are not possible
        assertNotEquals(encryptedSecret, encryptedSecretDuplicate);
        assertTrue(decryptionKeyStore.isEncryptedSecret(encryptedSecret));
        assertTrue(decryptionKeyStore.isEncryptedSecret(encryptedSecretDuplicate));

        String decodedSecret = decryptionKeyStore.decodeAndDecrypt(encryptedSecret);
        assertEquals(secret, decodedSecret);

        String decodedSecretDuplicate = decryptionKeyStore.decodeAndDecrypt(encryptedSecretDuplicate);
        assertEquals(secret, decodedSecretDuplicate);
    }

    @SneakyThrows
    protected String readFile(String path) {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path);
        return IOUtils.toString(inputStream, Charset.defaultCharset());
    }

}