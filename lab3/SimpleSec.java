import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SimpleSec {

    /***********************************************************************************/
    // Global Varibales
    /***********************************************************************************/
    static final String PUBLIC_KEY_FILENAME = ".public.key";
    static final String PRIVATE_KEY_FILENAME = ".private.key";
    static final RSALibrary RSA = new RSALibrary();
    static final SymmetricCipher AES = new SymmetricCipher();
    static final int[] VALID_KEY_SIZES = new int[]{16, 24, 32};
    static final int AES_KEY_SIZE = 128;

    public static void usage(String e){
        System.err.printf("Error: %s", e);
        System.err.println("""
            Usage:\njava Simplec command <SourceFile> <DestinationFile>
            g|         Generate a pair of RSA keys
            e|         Encrypt and sign SourceFile
            d|         Decrypt private key and SourceFile
            """);
            System.exit(-1);
    }

    public static void main(String[] args) {
        
        switch (args[0]) {
            case "g":
                try {
                    generateKeysAndEncryptPrivKey();
                } catch (Exception e) {
                    RSALibrary.handleException("Generating RSA keys", e);
                }
                break;

            case "e":
                //java SimpleSec command [sourceFile] [destinationFile]
                if (args.length != 3){
                    usage("2 parameters must be provided when using 'e' commands");
                }

                try {
                   //  encryptAndSign(String source_file, String destination_file)

                } catch (Exception e) {
                    RSALibrary.handleException("Encrypting", e);
                }
                break;

            case "d":
                if (args.length != 3){
                    usage("2 parameters must be provided when using 'd'command");
                }

                try {
                    // decrypt(String encrypted_file, String outputfile)
                } catch (Exception e) {
                    RSALibrary.handleException("Decrypting", e);
                }
                break;

            default:
                usage("Unkown command provided");
                break;
        }

    }   // End of main()

    public static String getPassPhrase(){
        Scanner sc = new Scanner(System.in);
        String passphrase = "";
        boolean valid_key = false;
        
        do {
            // Ask user for valid passphrase
            System.out.println("\n Enter a passphrase with a valid length (16, 24, or 32 characters):");
            passphrase = sc.nextLine();

            // Check key's length is valid
            for (int num : VALID_KEY_SIZES) {
                if (num == passphrase.length()){
                    valid_key = true;
                }
            }
        } while (!valid_key);

        sc.close();
        return passphrase;
    }

    public static void generateKeysAndEncryptPrivKey(){
        try{
            RSA.generateKeys();
        }catch(Exception e){
            RSALibrary.handleException("Generating RSA keys", e);
        }
        String passphrase = getPassPhrase();
        byte[] aesKey = passphrase.getBytes();

        try{
            //Read the file where the pub key is stored.
            byte[] privKey = readKey(PRIVATE_KEY_FILENAME);
        }catch(Exception e){
            RSALibrary.handleException("Reading private key", e);
        }

        try{
            AES.encryptCBC(privKey, aesKey);
        }


    }

    /* Given the rsa key filepath
     * copy the bytes of the file into byte[] pubKey 
     * then return the variable
     * */ 
    public static byte[] readKey(String key_filename){
        byte[] rsa_key = null;
        rsa_key = readFile(key_filename);
        if (rsa_key.length == 0) {
            generateKeysAndEncryptPrivKey();
            return readKey(key_filename);
        }
        return rsa_key;
    }

    public void encryptAndSign(String source_file, String destination_file){
        // Read file into inpoutstream -> byte[]
        
        byte[] source_bytes = null;
        
        try{
            source_bytes = readFile(source_file);
        }catch(Exception e){
            // recomiendo usar tu funcion
            // RSALibrary.handleException("Could not read source file", e); -----------------------
            System.err.println("ERROR: Could not read source file: " + e.getMessage());
            return; // Solo es necesario poner return si la función no devuelve void ---------------------
        }
        // If plaintext is empty, something is wrong
        if (source_bytes == null) return;

        try{
            // Ask the user for the passphrase to decrypt their private key
            String passphrase = getPassPhrase();

            //Read the file where the private key encrypted with AES is stored.
            byte[] encrypted_private_key = readKey(PRIVATE_KEY_FILENAME);

            //Decrypt the private key using AES/CBC with the passphrase as the key.
            byte[] decrypted_private_key = AES.decryptCBC(encrypted_private_key, passphrase.getBytes());

            // We reconstruct the RSA private key from the decrypted bytes
            PrivateKey privkey = generatePrivateKeyFromBytes(decrypted_private_key);

            //  Generate random AES key to encrypt the file
            KeyGenerator keyGenAES = KeyGenerator.getInstance("AES");
            keyGenAES.init(128);
            SecretKey aesSecretKey = keyGenAES.generateKey();
            byte[] aes_key = aesSecretKey.getEncoded();

            // Encrypt file with the generated
            byte[] ciphertext = AES.encryptCBC(source_bytes, aes_key);

            // Encrypt AES key with RSA public key
            byte[] pubKey = readKey(PUBLIC_KEY_FILENAME);
            // Transform byte[] pubKey into PublicKey public_key
            PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(pubKey);
            keyfactory = KeyFactory.getInstance("RSA");
            PublicKey public_key = keyfactory.generatePublic(pubKeySpec);
            
            byte[] encryptedAesKey = RSA.encrypt(aes_key, public_key);

            //  Concatenate encryptedAesKey + encrypted text to sign
            byte[] dataToSign = new byte[encryptedAesKey.length + ciphertext.length];
            System.arraycopy(encryptedAesKey, 0, dataToSign, 0, encryptedAesKey.length);
            System.arraycopy(ciphertext, 0, dataToSign, encryptedAesKey.length, ciphertext.length);

            // Sign the concatenation
            byte[] signature = RSA.sign(dataToSign, privkey);

            // Finally concatenate: signature + encryptedAESkey + ciphertext
            byte[] outputData = new byte[signature.length + dataToSign.length];
            System.arraycopy(signature, 0, outputData, 0, signature.length);
            System.arraycopy(dataToSign, 0, outputData, signature.length, dataToSign.length);

            // Save result
            try (FileOutputStream outputStream = new FileOutputStream(destination_file)) {
                outputStream.write(outputData);
            } catch (Exception e){}
        
        }catch(Exception e){}
    }

    public void decrypt(String encrypted_file, String outputfile){
        // Read signed encrypted file
        byte[] data_encrypted = null;
        try {
            data_encrypted = readFile(encrypted_file);
        } catch(Exception e) {} //ERROR: Could not read the encrypted file
        // Read the public key to determine block size, since public key and private have the same length
        byte[] public_key_bytes = readKey(PUBLIC_KEY_FILENAME);
        int rsa_key_size = public_key_bytes.length;
        PublicKey pubkey = null;
      
        pubkey = generatePublicKeyFromBytes(public_key_bytes);

        if (pubkey.length == 0){

        }
        
        // Separate: signature | encrypted AES key | encrypted text
        byte[] signature = new byte[rsa_key_size];
        byte[] encryptedAesKeyRandom = new byte[rsa_key_size];
        byte[] cipher_file = new byte[data_encrypted.length - signature.length - encryptedAesKeyRandom.length];

        System.arraycopy(data_encrypted, 0, signature, 0, signature.length);
        System.arraycopy(data_encrypted, signature.length, encryptedAesKeyRandom, 0, encryptedAesKeyRandom.length);
        System.arraycopy(data_encrypted, signature.length + encryptedAesKeyRandom.length, cipher_file, 0, cipher_file.length);
        
        // Request passphrase and decrypt private key
        askPassphrase();
        // Read encrypted private key
        byte[] encrypted_private_key = readKey(PRIVATE_KEY_FILE);
        // Decrypt private key with CBC/AES and passphrase
        byte[] decrypted_private_key = null;
        try{
            byte[] aes_key = passphrase.getBytes();
            decrypted_private_key = SymmetricCipher.decryptCBC(encrypted_private_key, aes_key);
        }catch (Exception e){} // ERROR: problem decrypting the private key with the passphrase

        // Rebuild key 




        // Decrypt AES key with private RSA key 
        // Descifrar la clave AES usando la clave privada RSA
        byte[] aes_key_random;
        try {
            aes_key_random = RSALibrary.decrypt(encryptedAesKeyRandom, privateKey); //ERROR: Could not decrypt the AES key.
        } catch (Exception e) {}
        // Decrypt content
        // Verify signature on (encryptedAesKey + cipher_file) with AES
        byte[] final_file_bytes = null;
        try {
            final_file_bytes = SymmetricCipher.decryptCBC(cipher_file, aes_key_random);
        } catch (Exception e) {} // ERROR: Failed to decrypt the file contents.
        // Decrypt passphrase/aes_key/session_key with private key
        // Decrypt ciphertext with the aes_key obatined in previous step
        boolean verified = RSALibrary.verify(final_file_bytes, signature, pubkey);
        if (!verified) {
            System.err.println("Invalid digital signature");
            System.exit(-1);
            return;
        } else {
            System.out.println("Correct and verified signature");
        }
        // Save decrypted ciphertext
        try (FileOutputStream outputStream = new FileOutputStream(outputfile)) {
            outputStream.write(final_file_bytes);
        }catch {} //ERROR: problem writing the decrypted file
    }

    public static byte[] readFile(String filename) {
        try (FileInputStream fis = new FileInputStream(filename)) {
            return fis.readAllBytes();
        } catch (FileNotFoundException e){
            RSALibrary.handleException("File not found", e);
            return new byte[0]; // safer than returning null
        } catch (Exception e) {
            RSALibrary.handleException("Reading file", e);
            return new byte[0]; // safer than returning null
        }
    }

    public static PublicKey generatePublicKeyFromBytes(byte[] public_key_bytes){
        try{
            X509EncodedKeySpec keyspec = new X509EncodedKeySpec(public_key_bytes);
            KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            return keyfactory.generatePublic(keyspec);
        } catch(Exception e){
            RSALibrary.handleException("Eeeo generating public key from bytes", e);
            return null;
        }
    }

    public static PrivateKey generatePrivateKeyFromBytes(byte[] private_key_bytes){
        try{
            X509EncodedKeySpec keyspec = new X509EncodedKeySpec(private_key_bytes);
            KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            return keyfactory.generatePrivate(keyspec);
        } catch(Exception e){
            RSALibrary.handleException("Eeeo generating private key from bytes", e);
            return null;
        }
    }

    public static byte[] AESRandomKeyGenerator(){
        try{
            KeyGenerator keyGenAES = KeyGenerator.getInstance("AES");
            keyGenAES.init(128);
            SecretKey aesSecretKey = keyGenAES.generateKey();
            return aesSecretKey.getEncoded();
        }catch(Exception e){
            RSALibrary.handleException("Generating AES key", e);
            return new byte[0];
        }
    }


}