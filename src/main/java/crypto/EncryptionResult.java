package crypto;

public record EncryptionResult(String encryptedSecret, String encryptedAesKey, String iv) {

    public String serialized() {
        return String.format("%s.%s.%s", encryptedSecret, encryptedAesKey, iv);
    }

    public static EncryptionResult deserialize(String serialized) {
        String[] splitted = serialized.split("\\.");
        return new EncryptionResult(splitted[0], splitted[1], splitted[2]);
    }

}
