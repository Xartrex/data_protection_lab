import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import javax.crypto.*;
import java.security.InvalidKeyException;
import static java.util.Arrays.fill; // Added by students

public class SymmetricCipher {

	// Block size for cipher, applied to plaintext to be splitted
	// Static so it can be used outside the class without object
	public static final int BLOCK_SIZE = 16;

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	
	// Initialization Vector (fixed)
	// 16 bytes -> 128 bits
	byte[] iv = new byte[] { 
		(byte)49, // 1
		(byte)50, // 2
		(byte)51, // 3
		(byte)52, // 4
		(byte)53, // 5
		(byte)54, // 6
		(byte)55, // 7
		(byte)56, // 8
		(byte)57, // 9
		(byte)48, // 10
		(byte)49, // 11
		(byte)50, // 12
		(byte)51, // 13
		(byte)52, // 14
		(byte)53, // 15
		(byte)54  // 16
	};

    /*************************************************************************************/
	/* Empty Constructor method */
    /*************************************************************************************/
	public void SymmetricCipher() {}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
		// Generate the plaintext with padding

		// 1) Calculate required padding
		int padding_length = BLOCK_SIZE - (input.length % BLOCK_SIZE);
		
		// 2) Adding extra block size padding if plaintext lentgh is multiple of block size
		if (padding_length == 0) { 
			padding_length = BLOCK_SIZE; 
		}

		// 3) Generating new byte array for plaintext padded, so longer array
		byte[] plaintext = new byte[input.length + padding_length];

		// Initialize also encryptedt text with same length
		byte[] ciphertext = new byte[input.length + padding_length];

		// copying input into plaintext variable	
		System.arraycopy(input, 0, plaintext, 0, input.length); 

		// 4) padding plaintext variable
		// The value of the padding must be the same as the padding length
		// So if there's a 2 bytes padding, it will be: (byte) 2 , (byte) 2
		fill(
			plaintext, 			// 	Array,
			input.length, 		// from_index(inclusive)
			plaintext.length, 	// to_index (exclusive)
			(byte) padding_length // filling_value
		);

		// Generate the ciphertext
		byte[] last_ciphered_block = Arrays.copyOf(iv, BLOCK_SIZE);
		byte[] xor_block = new byte[BLOCK_SIZE];
		byte[] encrypted_block = new byte[BLOCK_SIZE];
		SymmetricEncryption encryptor = new SymmetricEncryption(byteKey);


		for (int i = 0; i < plaintext.length; i += BLOCK_SIZE) {
			// Getting iteration block from plaintext
			System.arraycopy(plaintext, i, xor_block, 0, BLOCK_SIZE);

			// iteration_block XOR last_ciphered_block
			xor(xor_block, last_ciphered_block);
			
			// encrypting xor_block

			encrypted_block = encryptor.encryptBlock(xor_block);

			// Copying encrypted block into ciphertext byte[], at the correspondent position
			System.arraycopy(encrypted_block, 0, ciphertext, i, BLOCK_SIZE);

			// Careful, object1 = object2 is a pointer not a copy, to copy use Arrays.copyOf()
			last_ciphered_block = Arrays.copyOf(encrypted_block, BLOCK_SIZE);
		}
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
	
		byte [] finalplaintext = new byte[input.length];

		SymmetricEncryption decryptor = new SymmetricEncryption(byteKey);
		byte[] last_encrypted_block = new byte[BLOCK_SIZE];
		last_encrypted_block = iv;
		byte[] encrypted_block = new byte[BLOCK_SIZE];
		byte[] decrypted_block = new byte[BLOCK_SIZE];
		
		// Generate the plaintext
		for (int i = 0; i < finalplaintext.length; i += BLOCK_SIZE) {
			// Getting iteration block from ciphertext (input)
			System.arraycopy(input, i, encrypted_block, 0, BLOCK_SIZE);
			
			// Decryptying block
			decrypted_block = decryptor.decryptBlock(encrypted_block);

			// iteration_block XOR last_deciphered_block
			xor(decrypted_block, last_encrypted_block);

			// Copying decrypted block into finalplaintext byte[], at the correspondent position
			System.arraycopy(decrypted_block, 0, finalplaintext, i, BLOCK_SIZE);

			// Careful, object1 = object2 is a pointer not a copy, to copy use Arrays.copyOf()
			last_encrypted_block = Arrays.copyOf(encrypted_block, BLOCK_SIZE);
		}
		
		// Eliminate the padding from the last block
		// Getting value from last byte, & 0xFF so it is unsigned byte, avoiding overflow
		int padding_value = (int)finalplaintext[finalplaintext.length-1] & 0xFF; 

		byte[] unpadded = Arrays.copyOf(finalplaintext, finalplaintext.length - padding_value); // since padding_value = padding_length

		return unpadded;
	}


	public static void xor(byte[] a, byte[] b) {
		if (a.length != b.length) {
			throw new IllegalArgumentException("Arrays must have the same length for XOR");
		}
		for (int i = 0; i < a.length; i++) {
			a[i] ^= b[i]; // XOR directly in a
		}
	}
	
}


