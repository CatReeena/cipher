package com.secure.lab.cipher;

import jdk.net.SocketFlow;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

import static javax.crypto.Cipher.ENCRYPT_MODE;

@AllArgsConstructor
@RestController
public class AuthController {

    private static byte[] cipherMessage;

    static{

        KeyPair pair = null;
        try {
            pair = AuthService.generateRSAKeyPairs();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] publicKey = pair.getPublic().getEncoded();

        try (FileOutputStream out = new FileOutputStream("public")) {
            // write a byte sequence
            out.write(publicKey);

        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] privateKey = pair.getPrivate().getEncoded();

        try (FileOutputStream out = new FileOutputStream("private")) {
            // write a byte sequence
            out.write(privateKey);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Autowired
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@NonNull @RequestParam String username,
                                      @NonNull @RequestParam String password) throws NoSuchAlgorithmException {
        if(authService.storeUser(username, password)){
            return ResponseEntity.ok().build();
        }else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @PostMapping("/auth")
    public ResponseEntity<?> authenticate(@NonNull @RequestParam String username,
                                          @NonNull @RequestParam String password) throws NoSuchAlgorithmException {
        if(authService.authenticate(username, password)){
            return ResponseEntity.ok().build();
        }else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @GetMapping("/rsa-key")
    public ResponseEntity<?> generateRSAKeyPairs() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {


        File file = new File("public");

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
            String msg ="msg";
            byte[] cipherText = cipher.doFinal(msg.getBytes()) ;
            cipherMessage = cipherText;

        }
        catch (FileNotFoundException e) {
            System.out.println("File not found" + e);
        }
        catch (IOException ioe) {
            System.out.println("Exception while reading file " + ioe);
        }
        return ResponseEntity.ok().build();

    }

    @GetMapping("/test")
    public  ResponseEntity<?> test() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

        String decryptedMessage;
        if(cipherMessage == null){
            decryptedMessage = "No message left";
        }else {

            File file = new File("private");

            try (FileInputStream fin = new FileInputStream(file)) {
                // create FileInputStream object

                byte fileContent[] = new byte[(int) file.length()];

                // Reads up to certain bytes of data from this input stream into an array of bytes.
                fin.read(fileContent);

                PrivateKey pkRecovered = KeyFactory.getInstance("RS").generatePrivate(new PKCS8EncodedKeySpec(fileContent));

                //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

                //Initialize Cipher for DECRYPT_MODE
                cipher.init(Cipher.DECRYPT_MODE, pkRecovered);

                //Perform Decryption
                byte[] decryptedTextArray = cipher.doFinal(cipherMessage);
                decryptedMessage = new String(decryptedTextArray);

                System.out.println(new String(decryptedTextArray));
            }
        }
        return ResponseEntity.ok(decryptedMessage);
    }
}
