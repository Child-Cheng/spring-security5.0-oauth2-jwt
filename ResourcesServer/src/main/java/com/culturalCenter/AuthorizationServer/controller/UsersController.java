package com.culturalCenter.AuthorizationServer.controller;

import com.culturalCenter.AuthorizationServer.entity.Users;
import com.culturalCenter.AuthorizationServer.service.UsersService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.annotation.security.RolesAllowed;

/**
 * (Users)表控制层
 *
 * @author wulincheng
 * @since 2020-06-11 13:11:38
 */
@RestController
@RequestMapping("api")
public class UsersController {
    /**
     * 服务对象
     */
    @Resource
    private UsersService usersService;

    /**
     * 通过主键查询单条数据
     *
     * @param id 主键
     * @return 单条数据
     */
    @GetMapping("selectOne")
    public Users selectOne(Integer id) {
        return this.usersService.queryById(id);
    }

    @GetMapping("user/test")
    @RolesAllowed("user")
    public String Test(Integer id) {
        return "成功认证";
    }

    @GetMapping("admin/testAdmin")
    @RolesAllowed("ADMIN")
    public String TestAdmin(Integer id) {
        return "成功认证";
    }

    @GetMapping("test/testTest")
    @RolesAllowed("ADMIN")
    public String testTest(Integer id) {
        return "测试的";
    }


}