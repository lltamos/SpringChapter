package com.elmo.chapter2.domain;

import lombok.Data;

import java.security.Timestamp;
import java.util.ArrayList;

@Data
public class Role {

    private Long id;


    private String rolename;

    private String roledesc;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRolename() {
        return rolename;
    }

    public void setRolename(String rolename) {
        this.rolename = rolename;
    }

    public String getRoledesc() {
        return roledesc;
    }

    public void setRoledesc(String roledesc) {
        this.roledesc = roledesc;
    }

    public Timestamp getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Timestamp createTime) {
        this.createTime = createTime;
    }

    public ArrayList<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(ArrayList<Permission> permissions) {
        this.permissions = permissions;
    }

    private Timestamp createTime;


    //权限的列表
    private ArrayList<Permission> permissions;


    public Role(Long id, String rolename, String roledesc, Timestamp createTime, ArrayList<Permission> permissions) {
        this.id = id;
        this.rolename = rolename;
        this.roledesc = roledesc;
        this.createTime = createTime;
        this.permissions = permissions;
    }
}
