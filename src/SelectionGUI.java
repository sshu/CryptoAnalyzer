import javax.swing.*;

import java.awt.*;
import java.awt.event.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SelectionGUI extends JFrame{
	
	private final int WINDOW_WIDTH = 900;   // Window width
	private final int WINDOW_HEIGHT = 700;  // Window height
	private JTabbedPane mainTabbedPane;
	
	//AES Global Data
	private JRadioButton aes128;
	private JRadioButton aes192;
	private JRadioButton aes256;
	private JRadioButton aesECB;
	private JRadioButton aesCBC;
	private JTextArea aesPlaintextBox;
	private JTextArea aesCiphertextBox;
	private int aesKeySize;
	private JTextArea aesResults;
	
	//DES Global Data
	private JRadioButton desECB;
	private JRadioButton desCBC;
	private JTextArea desPlaintextBox;
	private JTextArea desCiphertextBox;
	private JTextArea desResults;
	private JCheckBox tripleDes;
	
	//RSA Global Data
	private JRadioButton rsa1024;
	private JRadioButton rsa2048;
	private JTextArea rsaPublicKeyBox;
	private JTextArea rsaPlaintextBox;
	private JTextArea rsaCiphertextBox;
	private JTextArea rsaResults;
	
	//ECC Global Data
	private JRadioButton ecc160;
	private JRadioButton ecc224;
	private JRadioButton ecc256;
	private JTextArea eccPublicKeyBox;
	private JTextArea eccPlaintextBox;
	private JTextArea eccCiphertextBox;
	private JTextArea eccResults;
	
	//Algorithm Objects
	private AESCBC aescbc;
	private AESECB aesecb;
	private DESCBC descbc;
	private DESECB desecb;
	private RSA rsa;
	private ECC ecc;
	
	public SelectionGUI()
	{		
		// Set the title bar text.
	      setTitle("Cryptography Algorithm Performance Analyzer");

	      // Set the size of the window.
	      setSize(WINDOW_WIDTH, WINDOW_HEIGHT);

	      // Specify an action for the close button.
	      setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	      
	      mainTabbedPane = new JTabbedPane();
	      add(mainTabbedPane);
	      
	      buildAESTab();
	      buildDESTab();
	      buildRSATab();
	      buildECCTab();
	      
	      initInstatiation();

	      // Display the window.
	      setVisible(true);
	}
	
	public void buildAESTab()
	{
		JPanel aesTab = new JPanel();
		aesTab.setLayout(new BorderLayout());
		
		JPanel aesSettings = new JPanel();//Create Panel with AES settings
		aesSettings.setLayout(new BoxLayout(aesSettings, BoxLayout.Y_AXIS));//Line up items in a single column
		
	    JPanel aesPrint = new JPanel();//Create Panel to print results
	    
	    aesTab.add(aesSettings, BorderLayout.LINE_START);
	    aesTab.add(aesPrint, BorderLayout.LINE_END);
	    
	    JLabel keySizeLbl = new JLabel();
	    keySizeLbl.setText("Select Desired Key Size");
	    aesSettings.add(keySizeLbl);
	    
	    aes128 = new JRadioButton("128-bit Key Size          ");
	    aes128.setSelected(true);
	    aes192 = new JRadioButton("192-bit Key Size          ");
	    aes256 = new JRadioButton("256-bit Key Size          ");
	       
	    ButtonGroup aesKeySize = new ButtonGroup();
	    aesKeySize.add(aes128);
	    aesKeySize.add(aes192);
	    aesKeySize.add(aes256);
	       
	    aesSettings.add(aes128);
	    aesSettings.add(aes192);
	    aesSettings.add(aes256);
	    
	    JLabel label1 = new JLabel();
	    label1.setText("Select Mode of Operation");
	    aesSettings.add(label1);
	    
	    aesECB = new JRadioButton("Electronic Codebook (ECB)");
	    aesECB.setSelected(true);
	    aesCBC = new JRadioButton("Cipher Block Chaining (CBC)");
	       
	    ButtonGroup aesMode = new ButtonGroup();
	    aesMode.add(aesECB);
	    aesMode.add(aesCBC);
	       
	    aesSettings.add(aesECB);
	    aesSettings.add(aesCBC);
	    
	    aesSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel plaintextLbl = new JLabel();
	    plaintextLbl.setText("Provide a Sample Plaintext:");
	    aesSettings.add(plaintextLbl);
	    
	    aesPlaintextBox = new JTextArea(1, 30);
	    aesPlaintextBox.setLineWrap(true);
	    JScrollPane scrollPlaintext = new JScrollPane(aesPlaintextBox);
	    aesSettings.add(scrollPlaintext);
	    aesSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel ciphertextLbl = new JLabel();
	    ciphertextLbl.setText("Your Ciphertext is:");
	    aesSettings.add(ciphertextLbl);
	    
	    aesCiphertextBox = new JTextArea(1, 30);
	    aesCiphertextBox.setLineWrap(true);
	    aesCiphertextBox.setEditable(false);
	    aesCiphertextBox.setBackground(Color.LIGHT_GRAY);
	    JScrollPane scrollCiphertext = new JScrollPane(aesCiphertextBox);
	    aesSettings.add(scrollCiphertext);
	    aesSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JButton aesEncrypt = new JButton("Calculate Encryption");
	    JButton aesDecrypt = new JButton("Calculate Decryption");
	    aesSettings.add(aesEncrypt);
	    aesSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    aesSettings.add(aesDecrypt);
	    
	    AESButtonHandler handler = new AESButtonHandler();
	    aesEncrypt.addActionListener(handler);
	    aesDecrypt.addActionListener(handler);
	    
	    aesResults = new JTextArea("Results will appear here", 35, 40);
	    aesResults.setLineWrap(true);
	    aesResults.setBackground(Color.BLACK);
	    aesResults.setForeground(Color.WHITE);
	    aesResults.setEditable(false);
	    
	    aesResults.setCaretPosition(aesResults.getDocument().getLength());
	    
	    JScrollPane scrollResults = new JScrollPane(aesResults);
	    aesPrint.add(scrollResults);
		
		mainTabbedPane.addTab("AES", aesTab);
	}
	
	public void buildDESTab()
	{
		JPanel desTab = new JPanel();
		desTab.setLayout(new BorderLayout());
		
		JPanel desSettings = new JPanel();//Create Panel with DES settings
		desSettings.setLayout(new BoxLayout(desSettings, BoxLayout.Y_AXIS));//Line up items in a single column
		
	    JPanel desPrint = new JPanel();//Create Panel to print results
	    
	    desTab.add(desSettings, BorderLayout.LINE_START);
	    desTab.add(desPrint, BorderLayout.LINE_END);
	    
	    JLabel label1 = new JLabel();
	    label1.setText("Select Mode of Operation");
	    desSettings.add(label1);
	    
	    desECB = new JRadioButton("Electronic Codebook (ECB)");
	    desECB.setSelected(true);
	    desCBC = new JRadioButton("Cipher Block Chaining (CBC)");
	       
	    ButtonGroup desMode = new ButtonGroup();
	    desMode.add(desECB);
	    desMode.add(desCBC);
	       
	    desSettings.add(desECB);
	    desSettings.add(desCBC);
	    
	    desSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    tripleDes = new JCheckBox("Run in Triple DES mode?");
	    desSettings.add(tripleDes);
	    
	    desSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel plaintextLbl = new JLabel();
	    plaintextLbl.setText("Provide a Sample Plaintext:");
	    desSettings.add(plaintextLbl);
	    
	    desPlaintextBox = new JTextArea(1, 30);
	    desPlaintextBox.setLineWrap(true);
	    JScrollPane scrollPlaintext = new JScrollPane(desPlaintextBox);
	    desSettings.add(scrollPlaintext);
	    desSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel ciphertextLbl = new JLabel();
	    ciphertextLbl.setText("Your Ciphertext is:");
	    desSettings.add(ciphertextLbl);
	    
	    desCiphertextBox = new JTextArea(1, 30);
	    desCiphertextBox.setLineWrap(true);
	    desCiphertextBox.setEditable(false);
	    desCiphertextBox.setBackground(Color.LIGHT_GRAY);
	    JScrollPane scrollCiphertext = new JScrollPane(desCiphertextBox);
	    desSettings.add(scrollCiphertext);
	    desSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JButton desEncrypt = new JButton("Calculate Encryption");
	    JButton desDecrypt = new JButton("Calculate Decryption");
	    desSettings.add(desEncrypt);
	    desSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    desSettings.add(desDecrypt);
	    
	    DESButtonHandler handler = new DESButtonHandler();
	    desEncrypt.addActionListener(handler);
	    desDecrypt.addActionListener(handler);
	    
	    desResults = new JTextArea("Results will appear here", 35, 40);
	    desResults.setLineWrap(true);
	    desResults.setBackground(Color.BLACK);
	    desResults.setForeground(Color.WHITE);
	    desResults.setEditable(false);
	    
	    desResults.setCaretPosition(desResults.getDocument().getLength());
	    
	    JScrollPane scrollResults = new JScrollPane(desResults);
	    desPrint.add(scrollResults);
		
		mainTabbedPane.addTab("DES", desTab);
	}
	
	public void buildRSATab()
	{		
		JPanel rsaTab = new JPanel();
		rsaTab.setLayout(new BorderLayout());
		
		JPanel rsaSettings = new JPanel();//Create Panel with DES settings
		rsaSettings.setLayout(new BoxLayout(rsaSettings, BoxLayout.Y_AXIS));//Line up items in a single column
		
	    JPanel rsaPrint = new JPanel();//Create Panel to print results
	    
	    rsaTab.add(rsaSettings, BorderLayout.LINE_START);
	    rsaTab.add(rsaPrint, BorderLayout.LINE_END);
	    
	    JLabel label1 = new JLabel();
	    label1.setText("Select Desired Key Size");
	    rsaSettings.add(label1);
	    
	    rsa1024 = new JRadioButton("1024-bit Key Size          ");
	    rsa1024.setSelected(true);
	    rsa2048 = new JRadioButton("2048-bit Key Size          ");
	       
	    ButtonGroup rsaKeySize = new ButtonGroup();
	    rsaKeySize.add(rsa1024);
	    rsaKeySize.add(rsa2048);
	       
	    rsaSettings.add(rsa1024);
	    rsaSettings.add(rsa2048);
	    
	    rsaSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel plaintextLbl = new JLabel();
	    plaintextLbl.setText("Provide a Sample Plaintext:");
	    rsaSettings.add(plaintextLbl);
	    
	    rsaPlaintextBox = new JTextArea(1, 30);
	    rsaPlaintextBox.setLineWrap(true);
	    JScrollPane scrollPlaintext = new JScrollPane(rsaPlaintextBox);
	    rsaSettings.add(scrollPlaintext);
	    rsaSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel publicKeyLbl = new JLabel();
	    publicKeyLbl.setText("Your generated public key is:");
	    rsaSettings.add(publicKeyLbl);
	    
	    rsaPublicKeyBox = new JTextArea(1, 30);
	    rsaPublicKeyBox.setLineWrap(true);
	    rsaPublicKeyBox.setEditable(false);
	    rsaPublicKeyBox.setBackground(Color.LIGHT_GRAY);
	    JScrollPane scrollPublicKey = new JScrollPane(rsaPublicKeyBox);
	    rsaSettings.add(scrollPublicKey);
	    rsaSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    rsaSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel ciphertextLbl = new JLabel();
	    ciphertextLbl.setText("Your Ciphertext is:");
	    rsaSettings.add(ciphertextLbl);
	    
	    rsaCiphertextBox = new JTextArea(1, 30);
	    rsaCiphertextBox.setLineWrap(true);
	    rsaCiphertextBox.setEditable(false);
	    rsaCiphertextBox.setBackground(Color.LIGHT_GRAY);
	    JScrollPane scrollCiphertext = new JScrollPane(rsaCiphertextBox);
	    rsaSettings.add(scrollCiphertext);
	    rsaSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JButton rsaEncrypt = new JButton("Calculate Encryption");
	    JButton rsaDecrypt = new JButton("Calculate Decryption");
	    rsaSettings.add(rsaEncrypt);
	    rsaSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    rsaSettings.add(rsaDecrypt);
	    
	    RSAButtonHandler handler = new RSAButtonHandler();
	    rsaEncrypt.addActionListener(handler);
	    rsaDecrypt.addActionListener(handler);
	    
	    rsaResults = new JTextArea("Results will appear here", 35, 40);
	    rsaResults.setLineWrap(true);
	    rsaResults.setBackground(Color.BLACK);
	    rsaResults.setForeground(Color.WHITE);
	    rsaResults.setEditable(false);
	    
	    rsaResults.setCaretPosition(rsaResults.getDocument().getLength());
	    
	    JScrollPane scrollResults = new JScrollPane(rsaResults);
	    rsaPrint.add(scrollResults);
		
		mainTabbedPane.addTab("RSA", rsaTab);
	}
	
	public void buildECCTab()
	{		
		JPanel eccTab = new JPanel();
		eccTab.setLayout(new BorderLayout());
		
		JPanel eccSettings = new JPanel();//Create Panel with ECC settings
		eccSettings.setLayout(new BoxLayout(eccSettings, BoxLayout.Y_AXIS));//Line up items in a single column
		
	    JPanel eccPrint = new JPanel();//Create Panel to print results
	    
	    eccTab.add(eccSettings, BorderLayout.LINE_START);
	    eccTab.add(eccPrint, BorderLayout.LINE_END);
	    
	    JLabel label1 = new JLabel();
	    label1.setText("Select Desired Key Size");
	    eccSettings.add(label1);
	    
	    ecc160 = new JRadioButton("160-bit Key Size          ");
	    ecc160.setSelected(true);
	    ecc224 = new JRadioButton("224-bit Key Size          ");
	    ecc256 = new JRadioButton("256-bit Key Size          ");
	       
	    ButtonGroup eccKeySize = new ButtonGroup();
	    eccKeySize.add(ecc160);
	    eccKeySize.add(ecc224);
	    eccKeySize.add(ecc256);
	       
	    eccSettings.add(ecc160);
	    eccSettings.add(ecc224);
	    eccSettings.add(ecc256);
	    
	    eccSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel plaintextLbl = new JLabel();
	    plaintextLbl.setText("Provide a Sample Plaintext:");
	    eccSettings.add(plaintextLbl);
	    
	    eccPlaintextBox = new JTextArea(1, 30);
	    eccPlaintextBox.setLineWrap(true);
	    JScrollPane scrollPlaintext = new JScrollPane(eccPlaintextBox);
	    eccSettings.add(scrollPlaintext);
	    eccSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel publicKeyLbl = new JLabel();
	    publicKeyLbl.setText("Your generated public key is:");
	    eccSettings.add(publicKeyLbl);
	    
	    eccPublicKeyBox = new JTextArea(1, 30);
	    eccPublicKeyBox.setLineWrap(true);
	    eccPublicKeyBox.setEditable(false);
	    eccPublicKeyBox.setBackground(Color.LIGHT_GRAY);
	    JScrollPane scrollPublicKey = new JScrollPane(eccPublicKeyBox);
	    eccSettings.add(scrollPublicKey);
	    eccSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    eccSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JLabel ciphertextLbl = new JLabel();
	    ciphertextLbl.setText("Your Ciphertext is:");
	    eccSettings.add(ciphertextLbl);
	    
	    eccCiphertextBox = new JTextArea(1, 30);
	    eccCiphertextBox.setLineWrap(true);
	    eccCiphertextBox.setEditable(false);
	    eccCiphertextBox.setBackground(Color.LIGHT_GRAY);
	    JScrollPane scrollCiphertext = new JScrollPane(eccCiphertextBox);
	    eccSettings.add(scrollCiphertext);
	    eccSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    
	    JButton eccEncrypt = new JButton("Calculate Encryption");
	    JButton eccDecrypt = new JButton("Calculate Decryption");
	    eccSettings.add(eccEncrypt);
	    eccSettings.add(Box.createRigidArea(new Dimension(0,10)));//Create spacing for formatting
	    eccSettings.add(eccDecrypt);
	    
	    ECCButtonHandler handler = new ECCButtonHandler();
	    eccEncrypt.addActionListener(handler);
	    eccDecrypt.addActionListener(handler);
	    
	    eccResults = new JTextArea("Results will appear here", 35, 40);
	    eccResults.setLineWrap(true);
	    eccResults.setBackground(Color.BLACK);
	    eccResults.setForeground(Color.WHITE);
	    eccResults.setEditable(false);
	    
	    eccResults.setCaretPosition(eccResults.getDocument().getLength());
	    
	    JScrollPane scrollResults = new JScrollPane(eccResults);
	    eccPrint.add(scrollResults);
		
		mainTabbedPane.addTab("Elliptic Curve", eccTab);
	}
	
	class AESButtonHandler implements ActionListener
	{
		private SecretKey aesKey;
		private String encryptedText;
		byte[] encryptedTextByte;
		private Cipher cipher;
		byte[] iv;
		
        public void actionPerformed(ActionEvent e)
        {
        	if(aes128.isSelected())
        		aesKeySize = 128;
        	else if(aes192.isSelected())
        		aesKeySize = 192;
        	else if(aes256.isSelected())
        		aesKeySize = 256;
        	
        	JButton sourceButton = (JButton)e.getSource();
        	if(sourceButton.getText().equals("Calculate Encryption"))
        	{
        		System.out.println("AES Encrypt");
        		if(aesECB.isSelected())
        		{
        			
        			try {
						encryptAESECB();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IllegalBlockSizeException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidAlgorithmParameterException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        		else if(aesCBC.isSelected())
        		{
        			try {
						encryptAESCBC();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidAlgorithmParameterException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IllegalBlockSizeException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        	}
        	else if(sourceButton.getText().equals("Calculate Decryption"))
        	{
        		System.out.println("AES Decrypt");
        		if(aesECB.isSelected())
        		{
        			try {
						decryptAESECB();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IllegalBlockSizeException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        		else if(aesCBC.isSelected())
        		{
        			try {
						decryptAESCBC();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidAlgorithmParameterException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IllegalBlockSizeException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        	}
        }
        
        private void encryptAESECB() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
        {
        	String aesPlaintext = aesPlaintextBox.getText();
        	aesecb = new AESECB(aesPlaintext, aesKeySize);
        	
        	aesResults.append("\n\n---------- Running in ECB Mode ----------");
    		aesResults.append("\n\nTime took to generate key of size " 
    				+ aesKeySize + " bits: "
    				+ aesecb.getKeyGenSecs() + " milliseconds.");
    		
    		System.out.println("Key is: " + Base64.getEncoder().encodeToString(aesecb.getAesKey().getEncoded()));
    		
    		cipher = Cipher.getInstance("AES");
    		
    		//Check for empty plaintext field
    		if(aesPlaintextBox.getText().equals(""))
    		{
    		    aesResults.append("\n\nPlaintext field is empty!");
    		}
    		else
    		{
    			aesecb.encrypt();
    			
    			aesResults.append("\n\nPlaintext is: " + aesPlaintext);    			
    			aesResults.append("\n\nCiphertext is: " + aesecb.getEncryptedText());
    			aesResults.append("\n\nAES Encryption Time: " + aesecb.getEncryptSecs() + " milliseconds.");
    			//aesResults.append("\n********************************************************************************");
    			
    			aesCiphertextBox.setText(aesecb.getEncryptedText());
    			System.out.println("Ciphertext is: " + aesecb.getEncryptedText());
    		}    		
        }
        
        private void encryptAESCBC() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
        	String aesPlaintext = aesPlaintextBox.getText();
        	aescbc = new AESCBC(aesPlaintext, aesKeySize);
    		
        	aesResults.append("\n\n---------- Running in CBC Mode ----------");
    		aesResults.append("\n\nTime took to generate key of size " 
    				+ aesKeySize + " bits: "
    				+ aescbc.getKeyGenSecs() + " milliseconds.");
    		
    		System.out.println("Key is: " + Base64.getEncoder().encodeToString(aescbc.getAesKey().getEncoded()));			
    		
    		//Check for empty plaintext field
    		if(aesPlaintextBox.getText().equals(""))
    		{
    		    aesResults.append("\n\nPlaintext field is empty!");
    		}
    		else
    		{
    			aescbc.encrypt();
    			
    			aesResults.append("\n\nPlaintext is: " + aesPlaintext);
    			aesResults.append("\n\nCiphertext is: " + aescbc.getEncryptedText());
    			aesResults.append("\n\nAES Encryption Time: " + aescbc.getEncryptSecs() + " milliseconds.");
    			//aesResults.append("\n********************************************************************************");
    			aesCiphertextBox.setText(aescbc.getEncryptedText());
    			System.out.println("Ciphertext is: " + aescbc.getEncryptedText());
    			
    		}    		
        }
        
        private void decryptAESECB() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
        {
        	aesecb.decrypt(); 
    		
    		aesResults.append("\n\nDecrypted Text is: " + aesecb.getDecryptedText());
    		aesResults.append("\n\nAES Decryption Time: " + aesecb.getDecryptSecs() + " milliseconds.");
    		aesResults.append("\n\nTotal AES Run Time: " + aesecb.getTotalSecs() + " milliseconds.");
			aesResults.append("\n********************************************************************************");
        }
        
        private void decryptAESCBC() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
        {    		
        	aescbc.decrypt();
        	
    		aesResults.append("\n\nDecrypted Text is: " + aescbc.getDecryptedText());
    		aesResults.append("\n\nAES Decryption Time: " + aescbc.getDecryptSecs() + " milliseconds.");
    		aesResults.append("\n\nTotal AES Run Time: " + aescbc.getTotalSecs() + " milliseconds.");
			aesResults.append("\n********************************************************************************");
        }
	}
	
	class DESButtonHandler implements ActionListener
	{
		private SecretKey desKey;
		private String encryptedText;
		byte[] encryptedTextByte;
		private Cipher cipher;
		byte[] iv;
		private String desType;
		
        public void actionPerformed(ActionEvent e)
        {
        	if(tripleDes.isSelected())
        		desType = "DESede";
        	else
        		desType = "DES";
        	
        	JButton sourceButton = (JButton)e.getSource();
        	if(sourceButton.getText().equals("Calculate Encryption"))
        	{
        		if(desECB.isSelected())
        		{
        			//AESECB aesECB = new AESECB(aesPlaintextBox.getText());
        			
        			try {
						encryptDESECB();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IllegalBlockSizeException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidAlgorithmParameterException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        		else if(desCBC.isSelected())
        		{
        			try {
						encryptDESCBC();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidAlgorithmParameterException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IllegalBlockSizeException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        	}
        	else if(sourceButton.getText().equals("Calculate Decryption"))
        	{
        		if(desECB.isSelected())
        		{
        			try {
						decryptDESECB();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IllegalBlockSizeException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        		else if(desCBC.isSelected())
        		{
        			try {
						decryptDESCBC();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidAlgorithmParameterException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IllegalBlockSizeException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
        		}
        	}
        }
        
        private void encryptDESECB() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
        {
        	String desPlaintext = desPlaintextBox.getText();
        	desecb = new DESECB(desPlaintext, desType);
        	
        	if(desType == "DESede")
        		desResults.append("\n\n---------- Triple DES Set! ----------");
        	
        	desResults.append("\n\n---------- Running in ECB Mode ----------");
        	desResults.append("\n\nTime took to generate key: "
    				+ desecb.getKeyGenSecs() + " milliseconds.");
    		
    		System.out.println("Key is: " + Base64.getEncoder().encodeToString(desecb.getDesKey().getEncoded()));
    		
    		//Check for empty plaintext field
    		if(desPlaintextBox.getText().equals(""))
    		{
    		    desResults.append("\n\nPlaintext field is empty!");
    		}
    		else
    		{
    			desecb.encrypt();
    			
    			desResults.append("\n\nPlaintext is: " + desPlaintext);    			
    			desResults.append("\n\nCiphertext is: " + desecb.getEncryptedText());
    			desResults.append("\n\nDES Encryption Time: " + desecb.getEncryptSecs() + " milliseconds.");
    			//desResults.append("\n********************************************************************************");
    			
    			desCiphertextBox.setText(desecb.getEncryptedText());
    			System.out.println("Ciphertext is: " + desecb.getEncryptedText());
    		}    		
        }
        
        private void encryptDESCBC() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
        	String desPlaintext = desPlaintextBox.getText();
        	descbc = new DESCBC(desPlaintext, desType);
    		
        	if(desType == "DESede")
        		desResults.append("\n\n---------- Triple DES Set! ----------");
        	
        	desResults.append("\n\n---------- Running in CBC Mode ----------");
        	desResults.append("\n\nTime took to generate key: "
    				+ descbc.getKeyGenSecs() + " milliseconds.");
    		
    		System.out.println("Key is: " + Base64.getEncoder().encodeToString(descbc.getDesKey().getEncoded()));			
    		
    		//Check for empty plaintext field
    		if(desPlaintextBox.getText().equals(""))
    		{
    			desResults.append("\n\nPlaintext field is empty!");
    		}
    		else
    		{
    			descbc.encrypt();
    			
    			desResults.append("\n\nPlaintext is: " + desPlaintext);
    			desResults.append("\n\nCiphertext is: " + descbc.getEncryptedText());
    			desResults.append("\n\nDES Encryption Time: " + descbc.getEncryptSecs() + " milliseconds.");
    			//desResults.append("\n********************************************************************************");
    			aesCiphertextBox.setText(descbc.getEncryptedText());
    			System.out.println("Ciphertext is: " + descbc.getEncryptedText());
    			
    		}    		
        }
        
        private void decryptDESECB() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
        {
        	desecb.decrypt(); 
    		
        	desResults.append("\n\nDecrypted Text is: " + desecb.getDecryptedText());
        	desResults.append("\n\nDES Decryption Time: " + desecb.getDecryptSecs() + " milliseconds.");
        	if(desType == "DES")
        		desResults.append("\n\nTotal DES Run Time: " + desecb.getTotalSecs() + " milliseconds.");
        	else
        		desResults.append("\n\nTotal Triple DES Run Time: " + desecb.getTotalSecs() + " milliseconds.");
        	desResults.append("\n********************************************************************************");
        }
        
        private void decryptDESCBC() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
        {    		
        	descbc.decrypt();
        	
        	desResults.append("\n\nDecrypted Text is: " + descbc.getDecryptedText());
        	desResults.append("\n\nDES Decryption Time: " + descbc.getDecryptSecs() + " milliseconds.");
        	if(desType == "DES")
        		desResults.append("\n\nTotal DES Run Time: " + descbc.getTotalSecs() + " milliseconds.");
        	else
        		desResults.append("\n\nTotal Triple DES Run Time: " + descbc.getTotalSecs() + " milliseconds.");
        	desResults.append("\n********************************************************************************");
        }
	}
	
	class RSAButtonHandler implements ActionListener
	{
		private PublicKey publicKey;
		private PrivateKey privateKey;
		private int keySize;
		private String encryptedText;
		byte[] encryptedTextByte;
		private Cipher cipher;
		
        public void actionPerformed(ActionEvent e)
        {
        	if(rsa1024.isSelected())
    		{
    			keySize = 1024;
    		}
    		else if(rsa2048.isSelected())
    		{
    			keySize = 2048;
    		}
        	
        	JButton sourceButton = (JButton)e.getSource();
        	if(sourceButton.getText().equals("Calculate Encryption"))
        	{
        		try {
					encryptRSA();
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IllegalBlockSizeException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (BadPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
        	}
        	else if(sourceButton.getText().equals("Calculate Decryption"))
        	{
        		try {
					decryptRSA();
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IllegalBlockSizeException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (BadPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
        	}
        }
        
        private void encryptRSA() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
        {
        	String rsaPlaintext = rsaPlaintextBox.getText();
        	rsa = new RSA(rsaPlaintext, keySize);
        	
        	rsaResults.append("\n\n---------- Generating a " + keySize + "-bit Key ----------");
        	rsaResults.append("\n\nTime took to generate key of size " 
    				+ keySize + " bits: "
    				+ rsa.getKeyGenSecs() + " milliseconds.");
        	rsaResults.append("\n\n" + rsa.getPublicKey());
        	
        	rsaPublicKeyBox.setText("" + rsa.getPublicKey());
        	
        	if(rsaPlaintextBox.getText().equals(""))
    		{
    		    rsaResults.append("\n\nPlaintext field is empty!");
    		}
        	else
    		{
    			rsa.encrypt();
    			
    			rsaResults.append("\n\nPlaintext is: " + rsaPlaintext);    			
    			rsaResults.append("\n\nCiphertext is: " + rsa.getEncryptedText());
    			rsaResults.append("\n\nRSA Encryption Time: " + rsa.getEncryptSecs() + " milliseconds.");
    			//rsaResults.append("\n********************************************************************************");
    			
    			rsaCiphertextBox.setText(rsa.getEncryptedText());
    			System.out.println("Ciphertext is: " + rsa.getEncryptedText());
    		} 
        }
        
        private void decryptRSA() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
        {
        	rsa.decrypt();
        	
        	rsaResults.append("\n\nDecrypted Text is: " + rsa.getDecryptedText());
        	rsaResults.append("\n\nRSA Decryption Time: " + rsa.getDecryptSecs() + " milliseconds.");
        	rsaResults.append("\n\nTotal RSA Run Time: " + rsa.getTotalSecs() + " milliseconds.");
        	rsaResults.append("\n********************************************************************************");
        }
	}
	
	class ECCButtonHandler implements ActionListener
	{
		private PublicKey publicKey;
		private PrivateKey privateKey;
		private int keySize;
		private String encryptedText;
		byte[] encryptedTextByte;
		private Cipher cipher;
		
        public void actionPerformed(ActionEvent e)
        {
        	if(ecc160.isSelected())
    		{
    			keySize = 160;
    		}
    		else if(ecc224.isSelected())
    		{
    			keySize = 224;
    		}
    		else if(ecc256.isSelected())
    		{
    			keySize = 256;
    		}
        	
        	JButton sourceButton = (JButton)e.getSource();
        	if(sourceButton.getText().equals("Calculate Encryption"))
        	{
        		try {
					encryptECC();
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IllegalBlockSizeException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (BadPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (InvalidAlgorithmParameterException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
        	}
        	else if(sourceButton.getText().equals("Calculate Decryption"))
        	{
        		try {
					decryptECC();
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IllegalBlockSizeException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (BadPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
        	}
        }
        
        private void encryptECC() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
        {
        	String eccPlaintext = eccPlaintextBox.getText();
        	ecc = new ECC(eccPlaintext, keySize);
        	
        	eccResults.append("\n\n---------- Generating a " + keySize + "-bit Key ----------");
        	eccResults.append("\n\nTime took to generate key of size " 
    				+ keySize + " bits: "
    				+ rsa.getKeyGenSecs() + " milliseconds.");
        	eccResults.append("\n\n" + ecc.getPublicKey());
        	
        	eccPublicKeyBox.setText("" + ecc.getPublicKey());
        	
        	if(eccPlaintextBox.getText().equals(""))
    		{
    		    eccResults.append("\n\nPlaintext field is empty!");
    		}
        	else
    		{
    			ecc.encrypt();
    			
    			eccResults.append("\n\nPlaintext is: " + eccPlaintext);    			
    			eccResults.append("\n\nCiphertext is: " + ecc.getEncryptedText());
    			eccResults.append("\n\nECC Encryption Time: " + ecc.getEncryptSecs() + " milliseconds.");
    			//rsaResults.append("\n********************************************************************************");
    			
    			eccCiphertextBox.setText(ecc.getEncryptedText());
    			System.out.println("Ciphertext is: " + ecc.getEncryptedText());
    		} 
        }
        
        private void decryptECC() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
        {
        	ecc.decrypt();
        	
        	eccResults.append("\n\nDecrypted Text is: " + ecc.getDecryptedText());
        	eccResults.append("\n\nECC Decryption Time: " + ecc.getDecryptSecs() + " milliseconds.");
        	eccResults.append("\n\nTotal ECC Run Time: " + ecc.getTotalSecs() + " milliseconds.");
        	eccResults.append("\n********************************************************************************");
        }
	}
	
	public void initInstatiation()
	{
		try {
			aesecb = new AESECB("init", 128);
			aesecb.encrypt();
			aesecb.decrypt();
			
			aescbc = new AESCBC("init", 128);
			aescbc.encrypt();
			aescbc.decrypt();
			
			desecb = new DESECB("init", "DES");
			desecb.encrypt();
			desecb.decrypt();
			
			descbc = new DESCBC("init", "DES");
			descbc.encrypt();
			descbc.decrypt();
			
			desecb = new DESECB("init", "DESede");
			desecb.encrypt();
			desecb.decrypt();
			
			rsa = new RSA("init", 1024);
			rsa.encrypt();
			rsa.decrypt();
			
			ecc = new ECC("init", 160);
			ecc.encrypt();
			ecc.decrypt();
			
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void main (String []args)
	{
		new SelectionGUI();
	}

}
