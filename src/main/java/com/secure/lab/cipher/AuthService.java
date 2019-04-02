package com.secure.lab.cipher;


import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.Arrays;


@AllArgsConstructor
@Service
public class AuthService {

    @Autowired
    public final UserDAO userDAO;
    
    public boolean authenticate(String username, String password) throws NoSuchAlgorithmException {

        boolean authenticated;
        User user = userDAO.findFirstByName(username);
        if(user == null)
            authenticated = false;
        else{
            byte[] hash = getHashMD5(password, user.getSalt());
            if(Arrays.equals(hash,user.getHash())){
                authenticated = true;
            }else{
                authenticated = false;
            }
        }
        return authenticated;
    }


    public boolean storeUser(String username, String password) throws NoSuchAlgorithmException {
        boolean stored;
        if(userDAO.findFirstByName(username) == null) {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            byte[] hash = getHashMD5(password, salt);
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
    
}
