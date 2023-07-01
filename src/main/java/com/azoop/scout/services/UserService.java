package com.azoop.scout.services;

import com.azoop.scout.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("userService")
public class UserService {

    List<User> userList = new ArrayList<>();

    public UserService() {
        System.out.println("no args cont");
    }

    @Autowired
    public UserService(User user) {
        userList.add(user);
        userList.add(new User("abc", "abc", "abc@gmail.com"));
        userList.add(new User("xyz", "xyz", "xyz@gmail.com"));
    }

    public List<User> getUserList() {
        return this.userList;
    }

    public User getUserByName(String userName) {
        return this.userList.stream().filter(((user) -> user.getUserName().equals(userName))).findAny().orElse(null);

    }

    public User addUser(User user) {
        this.userList.add(user);
        return user;
    }
}
