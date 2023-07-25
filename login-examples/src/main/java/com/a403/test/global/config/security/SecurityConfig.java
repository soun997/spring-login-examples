package com.a403.test.global.config.security;

import com.a403.test.domain.model.UserRole;
import com.a403.test.domain.user.application.PrincipalOauth2UserService;
import com.a403.test.domain.user.application.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                // 인증
                .antMatchers("/security-login/info").authenticated()
                // 인가
                .antMatchers("/security-login/admin/**").hasAuthority(UserRole.ADMIN.name())
                .anyRequest().permitAll()
                .and()
                // Form Login 방식 적용
                .formLogin()
                // 로그인 할 때 사용할 파라미터들
                .usernameParameter("loginId")
                .passwordParameter("password")
                .loginPage("/security-login/login")     // 로그인 페이지 URL
                .defaultSuccessUrl("/security-login")   // 로그인 성공 시 이동할 URL
                .failureUrl("/security-login/login")    // 로그인 실패 시 이동할 URL
                .and()
                .logout()
                .logoutUrl("/security-login/logout")
                .invalidateHttpSession(true).deleteCookies("JSESSIONID")
                // OAuth 로그인
                .and()
                .oauth2Login()
                .loginPage("/security-login/login")
                .defaultSuccessUrl("/security-login")
                .userInfoEndpoint()
                .userService(principalOauth2UserService)
        ;
        http
                .exceptionHandling()
                .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                .accessDeniedHandler(new MyAccessDeniedHandler());
    }
}

//@Configuration
//@EnableWebSecurity
//@RequiredArgsConstructor
//public class SecurityConfig {
//
//    private final UserService userService;
//    private static String secretKey = "my-secret-key-123123";   // 이렇게 관리하면 안될 것 같은데...
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        return httpSecurity
//                .httpBasic().disable()
//                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .addFilterBefore(new JwtTokenFilter(userService, secretKey), UsernamePasswordAuthenticationFilter.class)
//                .authorizeRequests()
//                .antMatchers("/jwt-login/info").authenticated()
//                .antMatchers("/jwt-login/admin/**").hasAuthority(UserRole.ADMIN.name())
//                .and().build();
//    }
//}

//@Configuration
//@EnableWebSecurity
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/security-login/info").authenticated()
//                .antMatchers("/security-login/admin/**").hasAuthority(UserRole.ADMIN.name())
//                .anyRequest().permitAll()
//                .and()
//                .formLogin()
//                .usernameParameter("loginId")
//                .passwordParameter("password")
//                .loginPage("/security-login/login")
//                .defaultSuccessUrl("/security-login")
//                .failureUrl("/security-login/login")
//                .and()
//                .logout()
//                .logoutUrl("/security-login/logout")
//                .invalidateHttpSession(true).deleteCookies("JSESSIONID");
//    }
//}