package com.elimo.chapter4.dto;

import lombok.Data;

import java.io.Serializable;


/**
 * 用户
 */
@Data
public class User implements Serializable {
	private String username;
	private int age;
}
