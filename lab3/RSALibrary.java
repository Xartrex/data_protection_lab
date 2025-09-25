import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import javax.crypto.Cipher;
import java.security.spec.X509EncodedKeySpec; 
// To build a public key encoded according to the X.509 standard
import java.security.spec.PKCS8EncodedKeySpec; 
// Private key encoded according to the PKCS#8 standard
import javax.crypto.NoSuchPaddingException;
// Indicates that the padding scheme is not available
import java.security.InvalidKeyException;
// Indicates that the cryptographic key provided is invalid
import javax.crypto.IllegalBlockSizeException;
// Indicates that the data block size is not suitable for the cryptographic operation
import javax.crypto.BadPaddingException;
// Indicates an error in the padding of the data
import java.security.SignatureException;
// Exception related to failures during digital signature operations


public class RSALibrary {

  // String to hold name of the encryption algorithm.
  public final String ALGORITHM = "RSA";
  //String to hold the name of the private key file.
  public final String PRIVATE_KEY_FILE = "./private.key";
  private PrivateKey private_key;
  // String to hold name of the public key file.
  public final String PUBLIC_KEY_FILE = "./public.key";
  private PublicKey public_key;

  /***********************************************************************************/
   /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
   /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
   /* Throws IOException */
  /***********************************************************************************/
  public void generateKeys() throws IOException {
    try {  
      // Create and initialize the RSA key pair generator with 1024-bit key size
      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
      keyGen.initialize(1024);
	    // TO-DO: Use KeyGen to generate a public and a private key
      KeyPair keyPair = keyGen.generateKeyPair();
      PublicKey publicKey = keyPair.getPublic();
      PrivateKey privateKey = keyPair.getPrivate();
      // TO-DO: store the public key in the file PUBLIC_KEY_FILE
      // Encode the public key with X.509 standard and write it to a file (auto-closing stream)
	    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
      try (FileOutputStream publicKeyOS = new FileOutputStream(PUBLIC_KEY_FILE)) {
        publicKeyOS.write(publicKeySpec.getEncoded());
      }
      // TO-DO: store the private key in the file PRIVATE_KEY_FILE
      // Encode the private key with PKCS8 standard and write it to a file (auto-closing stream)
	    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
      try (FileOutputStream privateKeyOS = new FileOutputStream(PRIVATE_KEY_FILE)) {
        privateKeyOS.write(privateKeySpec.getEncoded());
      }

	  } catch (NoSuchAlgorithmException e) {
      System.out.println("Exception: " + e.getMessage());
      System.exit(-1);
	  }
  }

  // Helper method to process exceptions
  public static void handleException(String operation, Exception e) {
    if (e instanceof NoSuchAlgorithmException) {
      // Handle case when RSA algorithm or padding scheme is not available
      System.err.println("[" + operation + " Error] Unsupported algorithm: " + e.getMessage());
    } else if (e instanceof NoSuchPaddingException) {
      System.err.println("[" + operation + " Error] Unsupported algorithm: " + e.getMessage());
    } else if (e instanceof InvalidKeyException) {
      // Handle data size or padding related problems, potential tampering
      System.err.println("[" + operation + " Error] Invalid key provided: " + e.getMessage());
    } else if (e instanceof SignatureException) {
      System.err.println("[" + operation + " Error] Signature process failed: " + e.getMessage());
    } else if (e instanceof IllegalBlockSizeException || e instanceof BadPaddingException) {
      // Handle data size or padding related problems, potential tampering
      System.err.println("[" + operation + " Error] Data size or padding problem - possible tampering: " + e.getMessage());
    } else if (e instanceof FileNotFoundException) {
      // File has not found
      System.err.println("[" + operation + " Error] File has not found: " + e.getMessage());
    } else if (e instanceof IOException) {
      // Handle data size or padding related problems, potential tampering
      System.err.println("[" + operation + " Error] Reading / writing file: " + e.getMessage());
    } else {
      // Catch-all for any other exceptions
      System.err.println("[" + operation + " Error] Unexpected exception: " + e.getMessage());
      e.printStackTrace();
    }
  }

  /***********************************************************************************/
  /* Encrypts a plaintext using an RSA public key. */
  /* Arguments: the plaintext and the RSA public key */
  /* Returns a byte array with the ciphertext */
  /***********************************************************************************/
  public byte[] encrypt(byte[] plaintext, PublicKey key) {
    byte[] ciphertext = null;
    try {
      // Gets an RSA cipher object
      final Cipher cipher = Cipher.getInstance(ALGORITHM);
      // TO-DO: initialize the cipher object and use it to encrypt the plaintext
      cipher.init(Cipher.ENCRYPT_MODE, key);
      // Perform encryption on the plaintext byte array
      ciphertext = cipher.doFinal(plaintext);
    } catch (Exception e) {
      handleException("Encryption", e);
    }
    /*We have modified this part of the code to optimize exception handling in encryption 
    and decryption by calling an external function.*/
    return ciphertext;
  }

  /***********************************************************************************/
  /* Decrypts a ciphertext using an RSA private key. */
  /* Arguments: the ciphertext and the RSA private key */
  /* Returns a byte array with the plaintext */
  /***********************************************************************************/
  public byte[] decrypt(byte[] ciphertext, PrivateKey key) {
    byte[] plaintext = null;
    try {
      // Gets an RSA cipher object
      final Cipher cipher = Cipher.getInstance(ALGORITHM);
      // TO-DO: initialize the cipher object and use it to decrypt the ciphertext
	    cipher.init(Cipher.DECRYPT_MODE, key);
      plaintext = cipher.doFinal(ciphertext);
    } catch (Exception e) {
      handleException("Decryption", e);
    } 
    /*We have modified this part of the code to optimize exception handling in encryption 
    and decryption by calling an external function.*/
    return plaintext;
  }
  
  /***********************************************************************************/
  /* Signs a plaintext using an RSA private key. */
  /* Arguments: the plaintext and the RSA private key */
  /* Returns a byte array with the signature */
  /***********************************************************************************/
  public byte[] sign(byte[] plaintext, PrivateKey key) {
    byte[] signedInfo = null;
    try {
	  // Gets a Signature object
      Signature signature = Signature.getInstance("SHA1withRSA");
	  // TO-DO: initialize the signature oject with the private key
	    signature.initSign(key);
	  // TO-DO: set plaintext as the bytes to be signed
      signature.update(plaintext);
	  // TO-DO: sign the plaintext and obtain the signature (signedInfo)
      signedInfo = signature.sign();
    } catch (Exception e) {
      handleException("Signing", e);
      /*We have modified this part of the code to optimize exception 
      handling in encryption and decryption by calling an external function. */
    }
	  return signedInfo;
  }
	
  /***********************************************************************************/
  /* Verifies a signature over a plaintext */
  /* Arguments: the plaintext, the signature to be verified (signed) 
  /* and the RSA public key */
  /* Returns TRUE if the signature was verified, false if not */
  /***********************************************************************************/
  public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {
    boolean result = false;
      try {
        // Gets a Signature object
        Signature signature = Signature.getInstance("SHA1withRSA");
        // TO-DO: initialize the signature oject with the public key
        signature.initVerify(key);
        // TO-DO: set plaintext as the bytes to be veryfied
        signature.update(plaintext);
        // TO-DO: verify the signature (signed). Store the outcome in the boolean result
        result = signature.verify(signed);
      } catch (Exception e) {
        handleException("Verification", e);
        /*We have modified this part of the code to optimize exception 
        handling in encryption and decryption by calling an external function. */
      }
    return result;
  }

  

}



	

