package crypto;

import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeyStoreTest {

    @SneakyThrows
    @Test
    void encryptAndDecrypt() {
        String privateKeyContent = this.readFile("private_key_pkcs8.pem");
        String publicKeyContent = this.readFile("public_key.pem");

        KeyStore keyStore = new KeyStore(publicKeyContent, privateKeyContent);
        this.doEncryptAndDecrypt(keyStore);
    }

    @SneakyThrows
    @Test
    void encryptAndDecryptDevMode() {
        KeyStore keyStore = new KeyStore();
        this.doEncryptAndDecrypt(keyStore);
    }

    private void doEncryptAndDecrypt(KeyStore keyStore) {
        String secret = UUID.randomUUID().toString();
        String encryptedSecret = keyStore.encryptAndEncode(secret);
        String decodedSecret = keyStore.decodeAndDecrypt(encryptedSecret);
        assertEquals(secret, decodedSecret);

    }

    @SneakyThrows
    private String readFile(String path) {
        InputStream inputStream = KeyStore.class.getClassLoader().getResourceAsStream(path);
        return IOUtils.toString(inputStream, Charset.defaultCharset());
    }

}