import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ECC {
	
	private String plaintext;
	private int keySize;
	private String stdName;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private double keyGenSecs;
	private double encryptSecs;
	private double decryptSecs;
	private double totalSecs;
	private String encryptedText;
	private byte[] encryptedTextByte;
	private String decryptedText;
	
	public ECC(String plaintext, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		if(keySize == 160)
			stdName = "secp160r1";
		else if(keySize == 224)
			stdName = "secp224r1";
		else if(keySize == 256)
			stdName = "secp256r1";
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ECIES", "BC");
		generator.initialize(new ECGenParameterSpec(stdName));
		
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
		
		Cipher cipherEncrypt = Cipher.getInstance("ECIES");
		cipherEncrypt.init(Cipher.ENCRYPT_MODE, publicKey);
		
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
		Cipher cipherDecrypt = Cipher.getInstance("ECIES");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, privateKey);
		
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

	public String getPlaintext() {
		return plaintext;
	}

	public void setPlaintext(String plaintext) {
		this.plaintext = plaintext;
	}

	public int getKeySize() {
		return keySize;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}

	public String getStdName() {
		return stdName;
	}

	public void setStdName(String stdName) {
		this.stdName = stdName;
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

	public double getTotalSecs() {
		return totalSecs;
	}

	public void setTotalSecs(double totalSecs) {
		this.totalSecs = totalSecs;
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

	public String getDecryptedText() {
		return decryptedText;
	}

	public void setDecryptedText(String decryptedText) {
		this.decryptedText = decryptedText;
	}
}
