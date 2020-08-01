package com.culturalCenter.AuthorizationServer.entity;

import org.apache.ibatis.annotations.Many;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;

import java.io.Serializable;
import java.util.List;

/**
 * (Users)实体类
 *
 * @author wulincheng
 * @since 2020-06-11 12:28:52
 */
public class Users implements Serializable {
    private static final long serialVersionUID = 874316931532925897L;
    
    private Integer id;

    private String userName;
    
    private String userNo;
    
    private String password;

    private List<String> Roles;

//    @Select("select * from Role where id = #{id} ")
//    @Results({
//            @Result(id = true, column = "id", property = "id"),
//            @Result(column = "name", property = "name"),
//            @Result(column = "id", property = "pis", many = @Many(select = "com.mybatis.mapper.ProductInfoMapper.findProductInfoByTid"))
//    })
//    private List<Role> Role;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserNo() {
        return userNo;
    }

    public void setUserNo(String userNo) {
        this.userNo = userNo;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<String> getRoles() {
        return Roles;
    }

    public void setRoles(List<String> roles) {
        Roles = roles;
    }


}