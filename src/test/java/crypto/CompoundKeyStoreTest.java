package crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CompoundKeyStoreTest extends AbstractKeyStoreTest {

    @Override
    KeyStore encryptionKeyStore(String publicKeyContent) {
        return new CompoundKeyStore(publicKeyContent, false);
    }

    @Override
    KeyStore decryptionKeyStore(String privateKeyContent) {
        return new CompoundKeyStore(privateKeyContent);
    }

    @Test
    void testPreferHybridForEncryption() {
        CompoundKeyStore keyStore = new CompoundKeyStore();
        String encrypted = keyStore.encryptAndEncode("Very secret...");
        HybridRSAKeyStore hybridRSAKeyStore = new HybridRSAKeyStore();
        assertTrue(hybridRSAKeyStore.isEncryptedSecret(encrypted));
    }
}