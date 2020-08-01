package com.culturalCenter.AuthorizationServer.config;


import com.culturalCenter.AuthorizationServer.entity.JwtUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @description OAuth2服务器配置
 */
@Configuration
public class OAuth2Config {


    /**
     * AuthorizationServerConfigurer 需要配置三个配置-重写几个方法：
     * ClientDetailsServiceConfigurer：用于配置客户详情服务，指定存储位置
     * AuthorizationServerSecurityConfigurer：定义安全约束
     * AuthorizationServerEndpointsConfigurer：定义认证和token服务
     * <p>
     * <p>
     * Created by xw on 2017/3/16.
     * 2017-03-16 22:28
     */
    @Configuration
    @EnableAuthorizationServer
    public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
        Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationServerConfig.class);
        @Autowired
        private DataSource dataSource;
        // 注入认证管理器
        @Autowired
        private AuthenticationManager authenticationManager;

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            // 使用特定的方式存储client detail
            clients.withClientDetails(clientDetails());
        }

        /**
         * 配置token生成相关信息
         */
        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            //指定认证管理器
            endpoints.authenticationManager(authenticationManager);
            // 允许 GET、POST 请求获取 token，即访问端点：oauth/token
            endpoints.allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
            //指定token存储位置
            endpoints.tokenStore(tokenStore());
            // 自定义token生成方式
            TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            tokenEnhancerChain.setTokenEnhancers(Arrays.asList( customerEnhancer(),accessTokenConverter()));//customerEnhancer(),
            endpoints.tokenEnhancer(tokenEnhancerChain);

            // 配置TokenServices参数
            DefaultTokenServices tokenServices = (DefaultTokenServices) endpoints.getDefaultAuthorizationServerTokenServices();
            tokenServices.setTokenStore(endpoints.getTokenStore());
            tokenServices.setSupportRefreshToken(true);
            tokenServices.setClientDetailsService(endpoints.getClientDetailsService());
            tokenServices.setTokenEnhancer(endpoints.getTokenEnhancer());
            tokenServices.setAccessTokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(1)); // 1天
            endpoints.tokenServices(tokenServices);

            super.configure(endpoints);
        }


        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            security.checkTokenAccess("permitAll()");
            security.allowFormAuthenticationForClients();
        }


        /**
         * 定义clientDetails存储的方式-》Jdbc的方式，注入DataSource
         *
         * @return
         */
        @Bean
        public ClientDetailsService clientDetails() {
            return new JdbcClientDetailsService(dataSource);
        }


        /**
         * 配置AccessToken的存储方式：此处使用Jdbc存储
         * Token的可选存储方式
         * 1、InMemoryTokenStore
         * 2、JdbcTokenStore
         * 3、JwtTokenStore
         * 4、RedisTokenStore
         * 5、JwkTokenStore
         */
        @Bean
        public TokenStore tokenStore() {
            return new JdbcTokenStore(dataSource);
        }

        /**
         * 注入自定义token生成方式
         *
         * @return
         */
        @Bean
        public TokenEnhancer customerEnhancer() {
            return new CustomTokenEnhancer();
        }

        @Bean
        public TokenEnhancer accessTokenConverter() {
            final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//        KeyStoreKeyFactory keyStoreKeyFactory =
//                new KeyStoreKeyFactory(new ClassPathResource("mytest.jks"), "mypass".toCharArray());
//        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("mytest"));
            converter.setSigningKey("123");
            converter.setAccessTokenConverter(new CustomerAccessTokenConverter());
            return converter;
        }

    }

    /**
     *
     * token生成携带的信息
     *
     */
    public static class CustomTokenEnhancer implements TokenEnhancer {

        //添加自定义信息返回
        @Override
        public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
            final Map<String, Object> additionalInfo = new HashMap<>();
            JwtUser user = (JwtUser) authentication.getUserAuthentication().getPrincipal();
            additionalInfo.put("username", user.getUsername());
            additionalInfo.put("role", user.getAuthorities());
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
            return accessToken;
        }

    }

    /**
     * 自定义CustomerAccessTokenConverter 这个类的作用主要用于AccessToken的转换，
     * 默认使用DefaultAccessTokenConverter 这个装换器
     * DefaultAccessTokenConverter有个UserAuthenticationConverter，这个转换器作用是把用户的信息放入token中，
     * 默认只是放入username
     * <p>
     * 自定义了下这个方法，加入了额外的信息
     * <p>
     * Created by xw on 2017/3/20.
     * 2017-03-20 9:54
     */
    public static class CustomerAccessTokenConverter extends DefaultAccessTokenConverter {


        public CustomerAccessTokenConverter() {
            super.setUserTokenConverter(new CustomerUserAuthenticationConverter());
        }


        private class CustomerUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

            //生成token携带自定义信息
            @Override
            public Map<String, ?> convertUserAuthentication(Authentication authentication) {
                LinkedHashMap response = new LinkedHashMap();
    //			response.put("user_name", authentication.getName());
    //			response.put("name", ((JwtUser) authentication.getPrincipal()).getUsername());
    //			response.put("id", ((JwtUser) authentication.getPrincipal()).get);
    //			response.put("createAt", ((JwtUser) authentication.getPrincipal()).getCreateAt());
                if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
                    //设置授权权限
                    response.put("authorities", AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
                }

                return response;
            }
        }

    }
}

