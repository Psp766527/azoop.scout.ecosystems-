package com.azoop.scout.application;

import com.azoop.scout.helper.Constants;
import com.azoop.scout.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * This controller class will be used to expose some end points which will be used to authenticate the user &
 * authorize the user for specified resource.
 */
@RestController
@RequestMapping("/users")
@SuppressWarnings("All")
public class ScoutController {

    @Autowired
    @Qualifier("userService")
    private com.azoop.scout.services.UserService userService;

    @GetMapping("/getAll")
    public List<User> getAllUsers()
    {
        System.out.println(Constants.userName);
        return this.userService.getUserList();
    }

    @GetMapping("/{userName}")
    public User getUser(@PathVariable(value = "userName") String userName) {
        return this.userService.getUserByName(userName);
    }

    @PostMapping("/add")
    public User addUser(@RequestBody User user) {
        return this.userService.addUser(user);
    }
}
