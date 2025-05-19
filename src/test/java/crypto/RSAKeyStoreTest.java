package crypto;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RSAKeyStoreTest extends AbstractKeyStoreTest {


    @Override
    KeyStore encryptionKeyStore(String publicKeyContent) {
        return new RSAKeyStore(publicKeyContent, false);
    }

    @Override
    KeyStore decryptionKeyStore(String privateKeyContent) {
        return new RSAKeyStore(privateKeyContent);
    }

    @Test
    void isEncryptedSecret() {
        KeyStore keyStore = new RSAKeyStore();
        String secret = "secret";
        String encryptedSecret = keyStore.encryptAndEncode(secret);

        assertTrue(keyStore.isEncryptedSecret(encryptedSecret));
        assertFalse(keyStore.isEncryptedSecret("!"));
        assertFalse(keyStore.isEncryptedSecret("!".repeat(342)));
        assertFalse(keyStore.isEncryptedSecret("%".repeat(342)));
        assertFalse(keyStore.isEncryptedSecret(String.format("%s.%s.%s",
                "A".repeat(5),
                "X".repeat(344),
                "Y".repeat(24))));        //Corner case - waiting for a smart tester to pick this up
        assertTrue(keyStore.isEncryptedSecret("a".repeat(342)));
    }

}