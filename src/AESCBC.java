import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESCBC {

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
	
	public AESCBC(String plaintext, int aesKeySize) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {
		
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
	
	public void encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		
		//Generate IV of 128-bits
		iv = new byte[16];
		SecureRandom rand = new SecureRandom();
		rand.nextBytes(iv);
		
		//Set Cipher params and initialize
		Cipher cipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipherEncrypt.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
		
		byte[] plaintextByte = aesPlaintext.getBytes();
		
		long startTime = System.nanoTime();
		encryptedTextByte = cipherEncrypt.doFinal(plaintextByte);
		long endTime   = System.nanoTime();
		
		Base64.Encoder encoder = Base64.getEncoder();
		encryptedText = encoder.encodeToString(encryptedTextByte);
		
		long totalTime = endTime - startTime;
		encryptSecs = (double)totalTime / 1000000;

	}
	
	public void decrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");			

		//Must use the same IV used in encryption
		cipherDecrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
		
		long startTime = System.nanoTime();
		byte[] byteDecryptedText = cipherDecrypt.doFinal(encryptedTextByte);
		long endTime   = System.nanoTime();
		long totalTime = endTime - startTime;
		decryptSecs = (double)totalTime / 1000000;
		
		decryptedText = new String(byteDecryptedText);
		
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
