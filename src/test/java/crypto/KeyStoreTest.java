package crypto;


import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeyStoreTest {

    @Test
    void encryptAndDecrypt() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        String privateKeyContent = this.readFile("private_key_pkcs8.pem");
        String publicKeyContent = this.readFile("public_key.pem");

        KeyStore encryptionKeyStore = new KeyStore(publicKeyContent, false);
        KeyStore decryptionKeyStore = new KeyStore(privateKeyContent);
        this.doEncryptAndDecrypt(encryptionKeyStore, decryptionKeyStore);
    }

    @Test
    void encryptAndDecryptDevMode() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        KeyStore keyStore = new KeyStore();
        this.doEncryptAndDecrypt(keyStore, keyStore);
    }

    private void doEncryptAndDecrypt(KeyStore encryptionKeyStore, KeyStore decryptionKeyStore) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String secret = UUID.randomUUID().toString();
        String encryptedSecret = encryptionKeyStore.encryptAndEncode(secret);
        String decodedSecret = decryptionKeyStore.decodeAndDecrypt(encryptedSecret);
        assertEquals(secret, decodedSecret);

    }

    private String readFile(String path) throws IOException {
        InputStream inputStream = KeyStore.class.getClassLoader().getResourceAsStream(path);
        return IOUtils.toString(inputStream, Charset.defaultCharset());
    }

}