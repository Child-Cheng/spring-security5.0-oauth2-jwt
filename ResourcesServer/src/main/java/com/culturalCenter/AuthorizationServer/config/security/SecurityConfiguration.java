//package com.culturalCenter.AuthorizationServer.config.security;
//
//
//import com.culturalCenter.AuthorizationServer.config.JwtAuthenticationFilter;
//import com.culturalCenter.AuthorizationServer.filter.LoginAuthenticationFilter;
//import com.culturalCenter.AuthorizationServer.service.impl.UserDetailsServiceImpl;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//import org.springframework.web.filter.CorsFilter;
//
//
///**
// * 安全配置：
// *
// * @author : wulincheng
// * @date : 13:40 2020/6/9
// */
//
////@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)//启用方法级的权限认证
////@EnableWebSecurity
//public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
//    Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);
//
//
//    @Autowired
//    public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
//        // 存储内存
////        auth.authenticationProvider(new AuthProvider(userDetailsService(), passwordEncoder()));
//    }
//
//    @Override
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }
//
//    @Override
//    protected void configure(final HttpSecurity http) throws Exception {
//        logger.debug("http安全请求");
//        http.csrf().disable()
//                .cors()
//                .and()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .authorizeRequests()
//                .antMatchers("/oauth/**").permitAll()
////                .antMatchers(permitUris.split(",")).permitAll()
//                .antMatchers("/api/admin/**").hasRole("ADMIN")
//                .antMatchers("/api/user/**").hasRole("USERS")
//                .anyRequest().authenticated()
//                .and()
//                .exceptionHandling()
//                .and()
//                .addFilter(new LoginAuthenticationFilter(authenticationManager()))
//
////                .addFilterBefore(new MyExceptionHandleFilter(), LogoutFilter.class)
//        ;
//        // 添加自定义 JWT 过滤器
//        http.addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
//    }
//
//
//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        return new UserDetailsServiceImpl();
//    }
//
//    /*
//    * spring security 5.0之后加密格式改变了，SecurityConfig类中加入
//    //      return new BCryptPasswordEncoder();
//    * */
//    @Bean
//    BCryptPasswordEncoder passwordEncoder() {
//
//        return new BCryptPasswordEncoder();
//    }
//
//    /**
//     * 解决跨域问题
//     *
//     * @return
//     */
//    @Bean
//    public CorsFilter corsFilter() {
//        final UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
//        final CorsConfiguration corsConfiguration = new CorsConfiguration();
//        corsConfiguration.setAllowCredentials(true);
//        corsConfiguration.addAllowedOrigin("*");
//        corsConfiguration.addAllowedHeader("*");
//        corsConfiguration.addAllowedMethod("*");
//        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
//        return new CorsFilter(urlBasedCorsConfigurationSource);
//    }
//
//}
