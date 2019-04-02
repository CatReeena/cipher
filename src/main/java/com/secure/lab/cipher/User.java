package com.secure.lab.cipher;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Getter
@Setter
@Entity
public class User {
    @Id
    @GeneratedValue
    private Long id;
    private String name;
    private byte[] hash;
    private byte[] salt;

    public User(){}

    public User(String name, byte[] hash, byte[] salt) {
        this.name = name;
        this.hash = hash;
        this.salt = salt;
    }
}
