import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;

public class Main {

	public static void main(String[] args) throws Exception {
		var ciphertext = PBEWithHmacSHA256AndAES128_Cipher.encrypt("my passphrase", "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8)); 
		var decrypted = PBEWithHmacSHA256AndAES128_Cipher.decrypt("my passphrase", ciphertext); 
		System.out.println("Ciphertext (hex): " + HexFormat.of().formatHex(ciphertext));
		System.out.println("Decrypted (Utf8): " + new String(decrypted, StandardCharsets.UTF_8));
		System.out.println("Decrypted (hex):  " + HexFormat.of().formatHex(decrypted));
		System.out.println();
	}
}

class PBEWithHmacSHA256AndAES128_Cipher {
	private static final int BLOCK_LEN = 16; 							// for AES
	private static final int SALT_LEN = 16; 								
	private static final int IV_LEN = BLOCK_LEN; 						// for AES-CBC
	private static final int SALT_IV_LEN = SALT_LEN + IV_LEN;
	private static final int ITER = 200_000; 							// choose as high as possible while maintaining acceptable performance, typical values: a few 10,000 to 100,000
    private static final String ALGO = "PBEWithHmacSHA256AndAES_128";	// PBEWithHmacSHA512AndAES_256 can of course also be used as ALGO
    
    public static byte[] encrypt(final String password, final byte[] plaintext) throws Exception {
        var saltIvCiphertext = new byte[SALT_IV_LEN + plaintext.length + (BLOCK_LEN - plaintext.length % BLOCK_LEN)]; // (...) is the PKCS#7 padding length 
        var cipher = Cipher.getInstance(ALGO);
       	init(password, cipher, Cipher.ENCRYPT_MODE, saltIvCiphertext);
        cipher.doFinal(plaintext, 0, plaintext.length, saltIvCiphertext, SALT_IV_LEN);
        return saltIvCiphertext; 
    }

    public static byte[] decrypt(final String password, final byte[] saltIvCipherText) throws Exception {
        var cipher = Cipher.getInstance(ALGO);
    	init(password, cipher, Cipher.DECRYPT_MODE, saltIvCipherText); 
        return cipher.doFinal(saltIvCipherText, SALT_IV_LEN, saltIvCipherText.length - SALT_IV_LEN);
    }
    
    private static void init(String password, Cipher cipher, int mode, byte[] saltIvCiphertext) throws Exception {
    	if (mode == Cipher.ENCRYPT_MODE) { 
    	    byte[] saltIv = new byte[SALT_IV_LEN]; 
    	    new SecureRandom().nextBytes(saltIv);
    	    System.arraycopy(saltIv, 0, saltIvCiphertext, 0, SALT_IV_LEN);
     	} 
    	var pbeParamSpec = new PBEParameterSpec(Arrays.copyOfRange(saltIvCiphertext, 0, SALT_LEN), ITER, new IvParameterSpec(Arrays.copyOfRange(saltIvCiphertext, SALT_LEN, SALT_IV_LEN)));
        var pbeKey = SecretKeyFactory.getInstance(ALGO).generateSecret(new PBEKeySpec(password.toCharArray()));        
        cipher.init(mode, pbeKey, pbeParamSpec);
    }
 }
