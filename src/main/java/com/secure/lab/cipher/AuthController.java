package com.secure.lab.cipher;

import lombok.AllArgsConstructor;
import lombok.NonNull;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static javax.crypto.Cipher.ENCRYPT_MODE;

@AllArgsConstructor
@RestController
public class AuthController {

    private static byte[] rsaCipherMessage;
    private static byte[] elGamalCipherMessage;
    public static final String RSA_PUBLIC_PATH = "rsa_public.der";
    public static final String RSA_PRIVATE_PATH = "rsa_private.der";
    public static final String ELGAMAL_PUBLIC_PATH = "el_public.der";
    public static final String ELGAMAL_PRIVATE_PATH = "el_private.der";

    public static SecureRandom random;

    static{

        //Generate and store RSA private and public keys
        KeyPair rsaPair = null;
        try {
            rsaPair = AuthService.generateRSAKeyPairs();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] rsaPublicKey = rsaPair.getPublic().getEncoded();
        byte[] rsaPrivateKey = rsaPair.getPrivate().getEncoded();

        storeKey(rsaPublicKey, RSA_PUBLIC_PATH);
        storeKey(rsaPrivateKey, RSA_PRIVATE_PATH);

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator elGamalGenerator = null;
        try {
            elGamalGenerator = KeyPairGenerator.getInstance("ElGamal", "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        //Generate and store ElGamal private and public keys
        random = new SecureRandom();
        elGamalGenerator.initialize(256, random);

        KeyPair elGamalPair = elGamalGenerator.generateKeyPair();
        byte[] elGamalPubilcKey = elGamalPair.getPublic().getEncoded();
        byte[] elGamalPrivateKey = elGamalPair.getPrivate().getEncoded();

        storeKey(elGamalPubilcKey, ELGAMAL_PUBLIC_PATH);
        storeKey(elGamalPrivateKey, ELGAMAL_PRIVATE_PATH);
    }

    private static void storeKey(byte[] key, String s) {
        try (FileOutputStream out = new FileOutputStream(s)) {
            // write a byte sequence
            out.write(key);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Autowired
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@NonNull @RequestParam String username,
                                      @NonNull @RequestParam String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(authService.storeUser(username, password, HashAlgorithm.MD5)){
            return ResponseEntity.ok().build();
        }else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @PostMapping("/auth")
    public ResponseEntity<?> authenticate(@NonNull @RequestParam String username,
                                          @NonNull @RequestParam String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(authService.authenticate(username, password, HashAlgorithm.MD5)){
            return ResponseEntity.ok().build();
        }else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @PostMapping("/register-sha1")
    public ResponseEntity<?> registerSHA1(@NonNull @RequestParam String username,
                                      @NonNull @RequestParam String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(authService.storeUser(username, password, HashAlgorithm.SHA1)){
            return ResponseEntity.ok().build();
        }else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @PostMapping("/auth-sha1")
    public ResponseEntity<?> authenticateSHA1(@NonNull @RequestParam String username,
                                          @NonNull @RequestParam String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(authService.authenticate(username, password, HashAlgorithm.SHA1)){
            return ResponseEntity.ok().build();
        }else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @PostMapping("/rsa-in")
    public ResponseEntity<?> generateRSAKeyPairs(@NonNull @RequestParam String message) {

        File file = new File(RSA_PUBLIC_PATH);

        try (FileInputStream fin = new FileInputStream(file)) {
            // create FileInputStream object

            byte fileContent[] = new byte[(int)file.length()];

            // Reads up to certain bytes of data from this input stream into an array of bytes.
            fin.read(fileContent);
            PublicKey pkRecovered = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(fileContent));

            //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

            //Initialize Cipher for ENCRYPT_MODE
            cipher.init(ENCRYPT_MODE, pkRecovered);

            //Perform Encryption
            byte[] cipherText = cipher.doFinal(message.getBytes()) ;
            rsaCipherMessage = cipherText;

        }catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        return ResponseEntity.ok().build();
    }

    @GetMapping("/rsa-out")
    public  ResponseEntity<?> getRSAMessageLeft() {

        String decryptedMessage;
        if(rsaCipherMessage == null){
            decryptedMessage = "No message left for you";
        }else {

            File file = new File(RSA_PRIVATE_PATH);

            try (FileInputStream fin = new FileInputStream(file)) {
                // create FileInputStream object

                byte fileContent[] = new byte[(int) file.length()];

                // Reads up to certain bytes of data from this input stream into an array of bytes.
                fin.read(fileContent);

                PrivateKey pkRecovered = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(fileContent));

                //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

                //Initialize Cipher for DECRYPT_MODE
                cipher.init(Cipher.DECRYPT_MODE, pkRecovered);

                //Perform Decryption
                byte[] decryptedTextArray = cipher.doFinal(rsaCipherMessage);
                decryptedMessage = new String(decryptedTextArray);

            }catch (Exception e) {
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }
        }
        return ResponseEntity.ok(decryptedMessage);
    }

    @PostMapping("/elgamal-in")
    public ResponseEntity<?> generateElGamalKeyPairs(@NonNull @RequestParam String message) {

        File file = new File(ELGAMAL_PUBLIC_PATH);

        try (FileInputStream fin = new FileInputStream(file)) {
            // create FileInputStream object

            byte fileContent[] = new byte[(int)file.length()];

            // Reads up to certain bytes of data from this input stream into an array of bytes.
            fin.read(fileContent);

            Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");

            PublicKey pkRecovered = KeyFactory.getInstance("ElGamal").generatePublic(new X509EncodedKeySpec(fileContent));

            cipher.init(Cipher.ENCRYPT_MODE, pkRecovered, random);
            byte[] cipherText = cipher.doFinal(message.getBytes());
            elGamalCipherMessage = cipherText;
            //System.out.println("cipher: " + new String(cipherText));


        }catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        return ResponseEntity.ok().build();
    }

    @GetMapping("/elgamal-out")
    public  ResponseEntity<?> getElGamalMessageLeft() {

        String decryptedMessage;
        if(elGamalCipherMessage == null){
            decryptedMessage = "No message left for you";
        }else {

            File file = new File(ELGAMAL_PRIVATE_PATH);

            try (FileInputStream fin = new FileInputStream(file)) {
                // create FileInputStream object

                byte fileContent[] = new byte[(int) file.length()];

                // Reads up to certain bytes of data from this input stream into an array of bytes.
                fin.read(fileContent);

                PrivateKey pkRecovered = KeyFactory.getInstance("ElGamal").generatePrivate(new PKCS8EncodedKeySpec(fileContent));

                //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
                Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");

                //Initialize Cipher for DECRYPT_MODE
                cipher.init(Cipher.DECRYPT_MODE, pkRecovered);

                //Perform Decryption
                byte[] decryptedTextArray = cipher.doFinal(elGamalCipherMessage);
                decryptedMessage = new String(decryptedTextArray);

            }catch (Exception e) {
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }
        }
        return ResponseEntity.ok(decryptedMessage);
    }
}
