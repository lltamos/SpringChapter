package com.elmo.chapter2.domain;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.stereotype.Component;

import java.util.HashMap;

@Component
public class UserList {

    private HashMap<String, User> users = new HashMap<>();

    private UserList() {
        User user=new User();
        user.setId("00001");
        user.setUsername("lintao");
        user.setPassword("123456");
        user.setPhone("17600298778");
        users.put("lintao", user);
    }

    public User getUsers(String name) {
        return users.get(name);
    }

    public boolean selectUserNameIsExist(String name){
        return ObjectUtils.allNotNull(getUsers(name));
    }
}
