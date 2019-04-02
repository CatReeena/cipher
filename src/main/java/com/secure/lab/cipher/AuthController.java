package com.secure.lab.cipher;

import lombok.AllArgsConstructor;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

@AllArgsConstructor
@RestController
public class AuthController {

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

    @RequestMapping("/test")
    public String test(){
        return "Hi there";
    }


}
