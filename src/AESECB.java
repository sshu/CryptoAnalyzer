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

public class AESECB {
	
	private String ciphertext;
	private SecretKey aesKey;
	private int aesKeySize;
	private String encryptedText;
	private byte[] encryptedTextByte;
	private byte[] iv;
	private double keyGenSecs;
	private double encryptSecs;
	private double decryptSecs;
	private double totalSecs;
	private String aesPlaintext;
	private String decryptedText;
	
	public AESECB(String plaintext, int aesKeySize) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {
		
		//Generate AES Key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(aesKeySize);
		
		long startTime = System.nanoTime();
		this.aesKey = keyGenerator.generateKey();
		long endTime   = System.nanoTime();
		long totalTime = endTime - startTime;
		this.keyGenSecs = (double)totalTime / 1000000;
		
		this.aesKeySize = aesKeySize;
		this.aesPlaintext = plaintext;
	}
	
	public void encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipherEncrypt = Cipher.getInstance("AES");
		
		byte[] plaintextByte = aesPlaintext.getBytes();
		cipherEncrypt.init(Cipher.ENCRYPT_MODE, aesKey);
		
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
		Cipher cipherDecrypt = Cipher.getInstance("AES");
		
		Base64.Decoder decoder = Base64.getDecoder();
		cipherDecrypt.init(Cipher.DECRYPT_MODE, aesKey);
		
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

	public SecretKey getAesKey() {
		return aesKey;
	}

	public void setAesKey(SecretKey aesKey) {
		this.aesKey = aesKey;
	}

	public int getAesKeySize() {
		return aesKeySize;
	}

	public void setAesKeySize(int aesKeySize) {
		this.aesKeySize = aesKeySize;
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

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
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

	public String getAesPlaintext() {
		return aesPlaintext;
	}

	public void setAesPlaintext(String aesPlaintext) {
		this.aesPlaintext = aesPlaintext;
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

