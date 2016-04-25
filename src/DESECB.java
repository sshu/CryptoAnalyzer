import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class DESECB {
	
	private String ciphertext;
	private SecretKey desKey;
	private String encryptedText;
	private byte[] encryptedTextByte;
	private double keyGenSecs;
	private double encryptSecs;
	private double decryptSecs;
	private double totalSecs;
	private String desPlaintext;
	private String decryptedText;
	private String desType;
	
	public DESECB(String plaintext, String desType) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {
		
		//Generate DES Key
		KeyGenerator keyGenerator = KeyGenerator.getInstance(desType);
		
		long startTime = System.nanoTime();
		this.desKey = keyGenerator.generateKey();
		long endTime   = System.nanoTime();
		long totalTime = endTime - startTime;
		this.keyGenSecs = (double)totalTime / 1000000;
		
		this.desPlaintext = plaintext;
		this.desType = desType;
	}
	
	public void encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipherEncrypt = Cipher.getInstance(desType + "/ECB/PKCS5Padding");
		
		byte[] plaintextByte = desPlaintext.getBytes();
		cipherEncrypt.init(Cipher.ENCRYPT_MODE, desKey);
		
		long startTime = System.nanoTime();
		encryptedTextByte = cipherEncrypt.doFinal(plaintextByte);
		long endTime   = System.nanoTime();
		
		Base64.Encoder encoder = Base64.getEncoder();
		encryptedText = encoder.encodeToString(encryptedTextByte);
		
		long totalTime = endTime - startTime;
		encryptSecs = (double)totalTime / 1000000;
	}
	
	public void decrypt() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher cipherDecrypt = Cipher.getInstance(desType + "/ECB/PKCS5Padding");
		
		cipherDecrypt.init(Cipher.DECRYPT_MODE, desKey);
		
		long startTime = System.nanoTime();
		byte[] decryptedByte = cipherDecrypt.doFinal(encryptedTextByte);
		long endTime   = System.nanoTime();
		long totalTime = endTime - startTime;
		decryptSecs = (double)totalTime / 1000000;
		
		decryptedText = new String(decryptedByte);
		
		calcTotalTime();
	}
	
	public void calcTotalTime()
	{
		totalSecs = keyGenSecs + encryptSecs + decryptSecs;
	}

	public String getCiphertext() {
		return ciphertext;
	}

	public void setCiphertext(String ciphertext) {
		this.ciphertext = ciphertext;
	}

	public SecretKey getDesKey() {
		return desKey;
	}

	public void setDesKey(SecretKey desKey) {
		this.desKey = desKey;
	}

	public String getEncryptedText() {
		return encryptedText;
	}

	public void setEncryptedText(String encryptedText) {
		this.encryptedText = encryptedText;
	}

	public byte[] getEncryptedTextByte() {
		return encryptedTextByte;
	}

	public void setEncryptedTextByte(byte[] encryptedTextByte) {
		this.encryptedTextByte = encryptedTextByte;
	}

	public double getKeyGenSecs() {
		return keyGenSecs;
	}

	public void setKeyGenSecs(double keyGenSecs) {
		this.keyGenSecs = keyGenSecs;
	}

	public double getEncryptSecs() {
		return encryptSecs;
	}

	public void setEncryptSecs(double encryptSecs) {
		this.encryptSecs = encryptSecs;
	}

	public double getDecryptSecs() {
		return decryptSecs;
	}

	public void setDecryptSecs(double decryptSecs) {
		this.decryptSecs = decryptSecs;
	}

	public String getDesPlaintext() {
		return desPlaintext;
	}

	public void setDesPlaintext(String desPlaintext) {
		this.desPlaintext = desPlaintext;
	}

	public String getDecryptedText() {
		return decryptedText;
	}

	public void setDecryptedText(String decryptedText) {
		this.decryptedText = decryptedText;
	}

	public double getTotalSecs() {
		return totalSecs;
	}

	public void setTotalSecs(double totalSecs) {
		this.totalSecs = totalSecs;
	}
}
