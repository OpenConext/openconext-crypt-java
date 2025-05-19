package crypto;

class CompoundKeyStoreTest extends AbstractKeyStoreTest {


    @Override
    KeyStore encryptionKeyStore(String publicKeyContent) {
        return new CompoundKeyStore(publicKeyContent, false);
    }

    @Override
    KeyStore decryptionKeyStore(String privateKeyContent) {
        return new CompoundKeyStore(privateKeyContent);
    }
}