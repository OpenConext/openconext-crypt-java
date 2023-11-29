package crypto;

import lombok.SneakyThrows;

import javax.crypto.Cipher;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for encrypting and decrypting secrets with RSA private / public keys
 */
public class KeyStore {

    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    /**
     * Use this constructor for local development / testing where it does not matter which keypair encrypts and
     * decrypts. See the test suite for usages.
     */
    @SneakyThrows
    public KeyStore() {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        KeyPair pair = generator.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();
    }

    /**
     * Use this constructor if you have access to a keypair. See the README for how to create them. See the test
     * suite for usages.
     * @param publicKeyContent raw RSA public key
     * @param privateKeyContent raw RSA private key
     */
    @SneakyThrows
    public KeyStore(String publicKeyContent, String privateKeyContent) {
        privateKeyContent = stripPrivateKey(privateKeyContent);
        publicKeyContent = stripPublicKey(publicKeyContent);

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        this.privateKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        this.publicKey = kf.generatePublic(keySpecX509);
    }

    @SneakyThrows
    public String encryptAndEncode(String secret) {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = secret.getBytes(Charset.defaultCharset());
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }

    @SneakyThrows
    public String decodeAndDecrypt(String encodedEncryptedSecret) {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encodedEncryptedSecret));
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    private String stripPublicKey(String publicKey) {
        return publicKey.replaceAll("\\n|-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----", "");
    }

    private String stripPrivateKey(String privateKey) {
        return privateKey.replaceAll("\\n|-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----", "");
    }

}
