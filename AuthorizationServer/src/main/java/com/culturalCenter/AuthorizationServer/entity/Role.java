package com.culturalCenter.AuthorizationServer.entity;

import java.io.Serializable;

/**
 * (Role)实体类
 *
 * @author wulincheng
 * @since 2020-06-11 11:16:19
 */
public class Role implements Serializable {
    private static final long serialVersionUID = 766908637624163423L;
    
    private Integer id;
    
    private String roleName;
    
    private String roleNo;


    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getRoleNo() {
        return roleNo;
    }

    public void setRoleNo(String roleNo) {
        this.roleNo = roleNo;
    }

}