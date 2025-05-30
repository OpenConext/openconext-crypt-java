package crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HybridRSAKeyStoreTest extends AbstractKeyStoreTest {

    @Override
    KeyStore encryptionKeyStore(String publicKeyContent) {
        return new HybridRSAKeyStore(publicKeyContent, false);
    }

    @Override
    KeyStore decryptionKeyStore(String privateKeyContent) {
        return new HybridRSAKeyStore(privateKeyContent);
    }

    @Test
    void isEncryptedSecret() {
        KeyStore keyStore = new HybridRSAKeyStore();
        String secret = "Top secret message!!!!";
        String encryptedSecret = keyStore.encryptAndEncode(secret);

        assertTrue(keyStore.isEncryptedSecret(encryptedSecret));
        assertFalse(keyStore.isEncryptedSecret("!"));
        assertFalse(keyStore.isEncryptedSecret("a".repeat(342)));

        //Corner case - waiting for a smart tester to pick this up
        assertTrue(keyStore.isEncryptedSecret(String.format("%s.%s.%s",
                "A".repeat(5),
                "X".repeat(344),
                "Y".repeat(24))));
    }

    @Test
    void ensureCorrectModules() {
        String privateKeyContent = this.readFile("private_key_1024_pkcs8.pem");
        String publicKeyContent = this.readFile("public_key_1024.pem");

        assertThrows(IllegalArgumentException.class, () -> new HybridRSAKeyStore(publicKeyContent, false));
        assertThrows(IllegalArgumentException.class, () -> new HybridRSAKeyStore(privateKeyContent));
    }

}