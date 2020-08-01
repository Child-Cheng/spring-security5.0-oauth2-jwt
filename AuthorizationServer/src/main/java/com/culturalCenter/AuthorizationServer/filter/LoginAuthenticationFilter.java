package com.culturalCenter.AuthorizationServer.filter;

import com.culturalCenter.AuthorizationServer.Utils.JwtTokenUtils;
import com.culturalCenter.AuthorizationServer.entity.JwtUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.*;

/**
 * 登录时做处理
 */
public class LoginAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    Logger log = LoggerFactory.getLogger(this.getClass());

    private AuthenticationManager authenticationManager;

    public LoginAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        super.setFilterProcessesUrl("/api/login");
        //login
    }


    /**
     * 接收并解析用户登陆信息  /login,必须使用/login，和post方法才会进入此filter
     * 如果身份验证过程失败，就抛出一个AuthenticationException
     *
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if (request.getContentType().equals(MediaType.APPLICATION_JSON) ||
                request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE)) {
            ObjectMapper mapper = new ObjectMapper();
            UsernamePasswordAuthenticationToken authRequest = null;
            try (InputStream stream = request.getInputStream()) {
                Map<String, String> body = mapper.readValue(stream, Map.class);
                authRequest = new UsernamePasswordAuthenticationToken(
                        body.get("username"), body.get("password")
                );
                log.info("用户(登录名)：{} 正在进行登录验证。。。密码：{}", body.get("username"), body.get("password"));
            } catch (IOException e) {
                e.printStackTrace();
                authRequest = new UsernamePasswordAuthenticationToken("", "");
            } finally {
                setDetails(request, authRequest);
                //提交给自定义的provider组件进行身份验证和授权
                Authentication authentication = authenticationManager.authenticate(authRequest);
                return authentication;
            }
        } else {
            return super.attemptAuthentication(request, response);
        }
    }
}