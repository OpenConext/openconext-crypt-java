package crypto;

import java.util.List;

public class CompoundKeyStore implements KeyStore {

    private final List<KeyStore> keyStores;

    /**
     * Use this constructor for local development / testing where it does not matter which keypair encrypts and
     * decrypts. See the test suite for usages.
     */
    public CompoundKeyStore() {
        this.keyStores = List.of(
                new HybridRSAKeyStore(),
                new RSAKeyStore());
    }

    /**
     * Use this constructor if you need to encrypt secrets. See the README for how to create keys and see the test
     * suite for usages.
     *
     * @param publicKeyContent raw RSA public key
     * @param ignore           to differentiate between constructors
     */
    public CompoundKeyStore(String publicKeyContent, boolean ignore) {
        this.keyStores = List.of(
                new HybridRSAKeyStore(publicKeyContent, ignore),
                new RSAKeyStore(publicKeyContent, ignore));
    }

    /**
     * Use this constructor if you need to decrypt secrets. See the README for how to create keys and see the test
     * suite for usages.
     *
     * @param privateKeyContent raw RSA private key
     */
    public CompoundKeyStore(String privateKeyContent) {
        this.keyStores = List.of(
                new HybridRSAKeyStore(privateKeyContent),
                new RSAKeyStore(privateKeyContent)
        );
    }

    @Override
    public String encryptAndEncode(String secret) {
        //When we encrypt, use the new HybridRSAKeyStore
        KeyStore hybridKeyStore = this.keyStores.stream()
                .filter(keyStore -> keyStore instanceof HybridRSAKeyStore)
                .findFirst()
                .get();
        return hybridKeyStore.encryptAndEncode(secret);
    }

    @Override
    public String decodeAndDecrypt(String encodedEncryptedSecret) {
        KeyStore hybridKeyStore = this.keyStores.stream()
                .filter(keyStore -> keyStore.isEncryptedSecret(encodedEncryptedSecret))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No keystore found for this secret"));
        return hybridKeyStore.decodeAndDecrypt(encodedEncryptedSecret);
    }

    @Override
    public boolean isEncryptedSecret(String input) {
        return this.keyStores.stream().anyMatch(keyStore -> keyStore.isEncryptedSecret(input));
    }
}
