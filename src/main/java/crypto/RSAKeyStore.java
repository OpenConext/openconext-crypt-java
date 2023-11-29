package crypto;


import lombok.SneakyThrows;

import javax.crypto.Cipher;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Utility class for encrypting and decrypting secrets with RSA private / public keys
 */
public class RSAKeyStore implements KeyStore {

    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final Pattern base64Pattern = Pattern.compile("(([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?){1}");

    /**
     * Use this constructor for local development / testing where it does not matter which keypair encrypts and
     * decrypts. See the test suite for usages.
     */
    @SneakyThrows
    public RSAKeyStore() {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();
    }

    /**
     * Use this constructor if you have need to encrypt secrets. See the README for how to create keys and see the test
     * suite for usages.
     *
     * @param publicKeyContent raw RSA public key
     * @param ignore           to differentiate between constructors
     */
    @SneakyThrows
    public RSAKeyStore(String publicKeyContent, boolean ignore) {
        publicKeyContent = stripPublicKey(publicKeyContent);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        this.publicKey = kf.generatePublic(keySpecX509);
        this.privateKey = null;
    }

    /**
     * Use this constructor if you have need to decrypt secrets. See the README for how to create keys and see the test
     * suite for usages.
     *
     * @param privateKeyContent raw RSA private key
     */
    @SneakyThrows
    public RSAKeyStore(String privateKeyContent) {
        privateKeyContent = stripPrivateKey(privateKeyContent);

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        this.privateKey = kf.generatePrivate(keySpecPKCS8);
        this.publicKey = null;
    }

    @Override
    @SneakyThrows
    public String encryptAndEncode(String secret) {
        if (this.publicKey == null) {
            throw new IllegalArgumentException("For encryption a publicKey is required");
        }
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = secret.getBytes(Charset.defaultCharset());
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }

    @Override
    @SneakyThrows
    public String decodeAndDecrypt(String encodedEncryptedSecret) {
        if (this.privateKey == null) {
            throw new IllegalArgumentException("For encryption a privateKey is required");
        }
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encodedEncryptedSecret));
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    @Override
    public boolean isEncryptedSecret(String input) {
        return input.length() == 344 && base64Pattern.matcher(input).matches();
    }

    private String stripPublicKey(String publicKey) {
        return publicKey.replaceAll("\\n|-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----", "");
    }

    private String stripPrivateKey(String privateKey) {
        return privateKey.replaceAll("\\n|-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----", "");
    }

}
