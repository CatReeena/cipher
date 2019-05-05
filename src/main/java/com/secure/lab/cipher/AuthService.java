package com.secure.lab.cipher;


import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;


@AllArgsConstructor
@Service
public class AuthService {

    @Autowired
    public final UserDAO userDAO;
    
    public boolean authenticate(String username, String password, HashAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {

        boolean authenticated;
        User user = userDAO.findFirstByName(username);
        if(user == null)
            authenticated = false;
        else{
            byte[] hash;
            switch (algorithm){
                case MD5: hash = getHashMD5(password, user.getSalt());
                    break;
                default: hash = getHashSHA1(password, user.getSalt());
            }
            if(Arrays.equals(hash,user.getHash())){
                authenticated = true;
            }else{
                authenticated = false;
            }
        }
        return authenticated;
    }


    public boolean storeUser(String username, String password, HashAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        boolean stored;
        if(userDAO.findFirstByName(username) == null) {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            byte[] hash;
            switch (algorithm){
                case MD5: hash = getHashMD5(password, salt);
                break;
                default: hash = getHashSHA1(password, salt);
            }
            User user = new User(username, hash, salt);
            userDAO.save(user);
            stored = true;
        }else{
            stored = false;
        }
        return stored;
     }

    private byte[] getHashMD5(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(salt);
        return md.digest(password.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] getHashSHA1(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return hash;
    }


    public static KeyPair generateRSAKeyPairs() throws NoSuchAlgorithmException {
        // Get an instance of the RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);

        // Generate the KeyPair
        return keyPairGenerator.generateKeyPair();
    }
    
}
