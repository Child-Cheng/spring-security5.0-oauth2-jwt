package com.culturalCenter.AuthorizationServer.service.impl;

import com.culturalCenter.AuthorizationServer.Utils.AuthErrorEnum;
import com.culturalCenter.AuthorizationServer.entity.JwtUser;
import com.culturalCenter.AuthorizationServer.entity.Users;
import com.culturalCenter.AuthorizationServer.mapper.UsersMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Arrays;

/**
 * 从数据库读取授权类型
 * */
public class UserDetailsServiceImpl implements UserDetailsService {
    Logger logger = LoggerFactory.getLogger(this.getClass());
    @Autowired
    private UsersMapper usersMapper;

    /**
     * 根据用户名进行登录
     */
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Users user = usersMapper.findUserByUserName(s);

        if (user != null) {

            user.setRoles(Arrays.asList("ROLE_ADMIN", "ROLE_USER"));
//            user.setRoles(Arrays.asList("ADMIN", "USER"));
            UserDetails userDetails = new JwtUser(user);
            return userDetails;
        } else {
            logger.error("用户不存在");
//            throw new WrongUsernameException(AuthErrorEnum.LOGIN_NAME_ERROR.getMessage());
            return null;
        }
    }
}
