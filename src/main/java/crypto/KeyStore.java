package crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public interface KeyStore {

    String encryptAndEncode(String secret) ;

    String decodeAndDecrypt(String encodedEncryptedSecret) ;

    boolean isEncryptedSecret(String input);
}
