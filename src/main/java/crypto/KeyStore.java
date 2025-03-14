package crypto;

public interface KeyStore {

    String encryptAndEncode(String secret);

    String decodeAndDecrypt(String encodedEncryptedSecret);

    boolean isEncryptedSecret(String input);
}
