package crypto;


import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for encrypting and decrypting secrets with RSA private / public keys
 */
public class HybridRSAKeyStore implements KeyStore {

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;
    private final SecretKey aesKey;

    /**
     * Use this constructor for local development / testing where it does not matter which keypair encrypts and
     * decrypts. See the test suite for usages.
     */
    @SneakyThrows
    public HybridRSAKeyStore() {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        this.publicKey = (RSAPublicKey) pair.getPublic();
        this.privateKey = (RSAPrivateKey) pair.getPrivate();
        this.aesKey = generateAESKey();
    }

    /**
     * Use this constructor if you need to encrypt secrets. See the README for how to create keys and see the test
     * suite for usages.
     *
     * @param publicKeyContent raw RSA public key
     * @param ignore           to differentiate between constructors
     */
    @SneakyThrows
    public HybridRSAKeyStore(String publicKeyContent, boolean ignore) {
        publicKeyContent = stripPublicKey(publicKeyContent);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        this.publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        int modulus = this.publicKey.getModulus().bitLength();
        if (modulus != 2048) {
            throw new IllegalArgumentException("Private key must have modulus of 2048, not " + modulus);
        }
        this.privateKey = null;
        this.aesKey = generateAESKey();
    }

    /**
     * Use this constructor if you have need to decrypt secrets. See the README for how to create keys and see the test
     * suite for usages.
     *
     * @param privateKeyContent raw RSA private key
     */
    @SneakyThrows
    public HybridRSAKeyStore(String privateKeyContent) {
        privateKeyContent = stripPrivateKey(privateKeyContent);

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        this.privateKey = (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);
        int modulus = this.privateKey.getModulus().bitLength();
        if (modulus != 2048) {
            throw new IllegalArgumentException("Private key must have modulus of 2048, not " + modulus);
        }

        this.publicKey = null;
        this.aesKey = null;
    }

    @Override
    @SneakyThrows
    public String encryptAndEncode(String secret) {
        if (this.publicKey == null) {
            throw new IllegalArgumentException("For encryption a publicKey is required");
        }
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Using CBC with PKCS5Padding is common
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedSecretBytes = aesCipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));
        byte[] iv = aesCipher.getIV(); // The initialization vector

        // 3. Encrypt the AES key with the RSA public key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Using ECB and PKCS1Padding for key encryption
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKeyBytes = rsaCipher.doFinal(aesKey.getEncoded());
        Base64.Encoder encoder = Base64.getEncoder();
        return new EncryptionResult(
                encoder.encodeToString(encryptedSecretBytes),
                encoder.encodeToString(encryptedAesKeyBytes),
                encoder.encodeToString(iv))
                .serialized();
    }

    @Override
    @SneakyThrows
    public String decodeAndDecrypt(String serializedEncryptionResult) {
        if (this.privateKey == null) {
            throw new IllegalArgumentException("For encryption a privateKey is required");
        }
        EncryptionResult encryptionResult = EncryptionResult.deserialize(serializedEncryptionResult);
        String base64EncryptedSecret = encryptionResult.encryptedSecret();
        String base64EncryptedAesKey = encryptionResult.encryptedAesKey();
        String base64Iv = encryptionResult.iv();

        byte[] encryptedAesKeyBytes = Base64.getDecoder().decode(base64EncryptedAesKey);
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] decryptedAesKeyBytes = rsaCipher.doFinal(encryptedAesKeyBytes);
        SecretKey aesKey = new SecretKeySpec(decryptedAesKeyBytes, "AES");

        // 2. Decrypt the secret String using the decrypted AES key and IV
        byte[] encryptedSecretBytes = Base64.getDecoder().decode(base64EncryptedSecret);
        byte[] ivBytes = Base64.getDecoder().decode(base64Iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
        byte[] decryptedSecretBytes = aesCipher.doFinal(encryptedSecretBytes);

        return new String(decryptedSecretBytes, StandardCharsets.UTF_8);
    }

    @Override
    public boolean isEncryptedSecret(String input) {
        long dotCount = input.chars().filter(c -> c == '.').count();
        if (dotCount != 2) {
            return false;
        }
        EncryptionResult encryptionResult = EncryptionResult.deserialize(input);
        return encryptionResult.encryptedAesKey().length() == 344 && encryptionResult.iv().length() == 24;
    }

    private String stripPublicKey(String publicKey) {
        return publicKey.replaceAll("\\n|-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----", "");
    }

    private String stripPrivateKey(String privateKey) {
        return privateKey.replaceAll("\\n|-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----", "");
    }

    private SecretKey generateAESKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

}
