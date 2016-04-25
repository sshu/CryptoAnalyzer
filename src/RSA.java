import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class RSA {
	
	private String ciphertext;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private int keySize;
	private String encryptedText;
	private byte[] encryptedTextByte;
	private byte[] iv;
	private double keyGenSecs;
	private double encryptSecs;
	private double decryptSecs;
	private double totalSecs;
	private String plaintext;
	private String decryptedText;
	private SecureRandom rand;
	
	public RSA(String plaintext, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		rand = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
	    generator.initialize(keySize, rand);
	    
	    long startTime = System.nanoTime();
	    KeyPair pair = generator.generateKeyPair();
	    long endTime   = System.nanoTime();
		long totalTime = endTime - startTime;
		this.keyGenSecs = (double)totalTime / 1000000;
	    
	    publicKey = pair.getPublic();
	    privateKey = pair.getPrivate();
	    
	    this.plaintext = plaintext;
	    this.keySize = keySize;
	}
	
	public void encrypt() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		byte[] plaintextByte = plaintext.getBytes();
		
		Cipher cipherEncrypt = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		cipherEncrypt.init(Cipher.ENCRYPT_MODE, publicKey, rand);
		
		long startTime = System.nanoTime();
		encryptedTextByte = cipherEncrypt.doFinal(plaintextByte);
		long endTime   = System.nanoTime();
		long totalTime = endTime - startTime;
		encryptSecs = (double)totalTime / 1000000;
		
		Base64.Encoder encoder = Base64.getEncoder();
		encryptedText = encoder.encodeToString(encryptedTextByte);
	}
	
	public void decrypt() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
	{
		Cipher cipherEncrypt = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		cipherEncrypt.init(Cipher.DECRYPT_MODE, privateKey);
		
		long startTime = System.nanoTime();
		byte[] byteDecryptedText = cipherEncrypt.doFinal(encryptedTextByte);
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

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public int getKeySize() {
		return keySize;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
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

	public String getPlaintext() {
		return plaintext;
	}

	public void setPlaintext(String plaintext) {
		this.plaintext = plaintext;
	}

	public String getDecryptedText() {
		return decryptedText;
	}

	public void setDecryptedText(String decryptedText) {
		this.decryptedText = decryptedText;
	}

	public SecureRandom getRand() {
		return rand;
	}

	public void setRand(SecureRandom rand) {
		this.rand = rand;
	}

	public double getTotalSecs() {
		return totalSecs;
	}

	public void setTotalSecs(double totalSecs) {
		this.totalSecs = totalSecs;
	}
}
