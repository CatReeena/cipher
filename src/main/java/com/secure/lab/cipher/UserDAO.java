package com.secure.lab.cipher;

import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface UserDAO extends CrudRepository<User, Long> {

    public List<User> findByName(String name);

    public User findFirstByName(String name);


}
