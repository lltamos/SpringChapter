package com.elmo.chapter2.domain;

import lombok.Data;

import java.util.HashSet;
import java.util.Set;
@Data
public class User {

    private String id;

    private String avatar;

    private String username;

    private String password;

    private String phone;


    private Integer state;


    private Set<Role> roles=new HashSet<>();
}
