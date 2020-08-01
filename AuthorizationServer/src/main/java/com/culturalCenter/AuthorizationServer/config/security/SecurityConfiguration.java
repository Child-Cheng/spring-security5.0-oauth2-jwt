package com.culturalCenter.AuthorizationServer.config.security;


import com.culturalCenter.AuthorizationServer.filter.LoginAuthenticationFilter;
import com.culturalCenter.AuthorizationServer.service.impl.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


/**
 * 安全配置：
 *
 * @author : wulincheng
 * @date : 13:40 2020/6/9
 */

@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)//启用方法级的权限认证
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);


    @Autowired
    public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
        // 存储内存
//        auth.authenticationProvider(new AuthProvider(userDetailsService(), passwordEncoder()));
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        logger.debug("http安全请求");
        http.csrf().disable()
                .cors()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/**").permitAll()
//                .antMatchers(permitUris.split(",")).permitAll()
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                .antMatchers("/api/user/**").hasRole("USERS")
                .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .and()
                .addFilter(new LoginAuthenticationFilter(authenticationManager()))

//                .addFilterBefore(new MyExceptionHandleFilter(), LogoutFilter.class)
        ;
    }


    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

//
//
//    @Value("${jwt.tokenHeader}")
//    private String tokenHeader;
//
//    @Value("${jwt.head}")
//    private String head;
//
//    /**
//     * 获取授权放行路径
//     */
//    @Value("${jwt.permitUris}")
//    private String permitUris;
//
//    /**
//     * 数据库中取出用户信息
//     */
//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        return new UserDetailsServiceImpl();
//    }
//
//    /**
//     * HTTP请求安全处理
//     * anyRequest          |   匹配所有请求路径
//     * access              |   SpringEl表达式结果为true时可以访问
//     * anonymous           |   匿名可以访问
//     * denyAll             |   用户不能访问
//     * fullyAuthenticated  |   用户完全认证可以访问（非remember-me下自动登录）
//     * hasAnyAuthority     |   如果有参数，参数表示权限，则其中任何一个权限可以访问
//     * hasAnyRole          |   如果有参数，参数表示角色，则其中任何一个角色可以访问
//     * hasAuthority        |   如果有参数，参数表示权限，则其权限可以访问
//     * hasIpAddress        |   如果有参数，参数表示IP地址，如果用户IP和参数匹配，则可以访问
//     * hasRole             |   如果有参数，参数表示角色，则其角色可以访问
//     * permitAll           |   用户可以任意访问
//     * rememberMe          |   允许通过remember-me登录的用户访问
//     * authenticated       |   用户登录后可访问
//     */
//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        logger.debug("http安全请求");
//        http.csrf().disable()
//                .cors()
//                .and()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .authorizeRequests()
//                .antMatchers("/oauth/**").permitAll()
//                .antMatchers(permitUris.split(",")).permitAll()
//                .antMatchers("/api/admin/**").hasRole("ADMIN")
//                .antMatchers("/api/user/**").hasRole("USERS")
//                .anyRequest().authenticated()
//                .and()
//                .exceptionHandling()
////                .addFilterBefore(new MyExceptionHandleFilter(), LogoutFilter.class)
//        ;
//
//    }
//
//    /**
//     * WEB安全
//     */
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        super.configure(web);
//    }
//
//    /**
//     * 身份验证管理生成器
//     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//      auth.userDetailsService(userDetailsService()).passwordEncoder(new BCryptPasswordEncoder());
//        //使用自定义的授权认证
////        auth.authenticationProvider(new AuthProvider(userDetailsService(), passwordEncoder()));
//    }
//
//    @Override
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }
//
////    /**
////     * 干掉默认的授权前缀
////     * */
////    @Bean
////    GrantedAuthorityDefaults grantedAuthorityDefaults() {
////        return new GrantedAuthorityDefaults(""); // Remove the ROLE_ prefix
////    }

    /*
    * spring security 5.0之后加密格式改变了，SecurityConfig类中加入
    //      return new BCryptPasswordEncoder();
    * */
    @Bean
    BCryptPasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

    /**
     * 解决跨域问题
     *
     * @return
     */
    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.addAllowedOrigin("*");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
        return new CorsFilter(urlBasedCorsConfigurationSource);
    }

}
