package com.elimo.chapter4.dto;

/**
 * 直接返回User对象暴露信息太多，这样的返回值是不安全的，所以我们更应该返回一个 DTO 对象，我们可称它为 UserOutputDTO
 */
public class UserOutputDTO {
    private String username;
    private int age;
}
