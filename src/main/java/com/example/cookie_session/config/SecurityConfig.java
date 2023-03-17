package com.example.cookie_session.config;

import com.example.cookie_session.config.service.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Bean
    public SessionAuthFilter authTokenFilter(){
        return new SessionAuthFilter(userDetailsService);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();

        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.cors().and().csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and()
                .authorizeHttpRequests().requestMatchers("/api/auth/**").permitAll()
                .and()
                .authorizeHttpRequests().requestMatchers("/api/test/**").permitAll()
                .anyRequest().authenticated();
        httpSecurity.authenticationProvider(authenticationProvider());
        httpSecurity.addFilterBefore(new SessionAuthFilter(userDetailsService), UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
//        httpSecurity.cors().and().csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
//                .and()
//                .authorizeHttpRequests().requestMatchers("/api/auth/**").permitAll()
//                .and()
//                .authorizeHttpRequests().requestMatchers("/api/test/**").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .sessionManagement()
//                .maximumSessions(1);
////                .sessionRegistry(sessionRegistry())
////                .and()
////                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
//
////                        .sessionFixation().migrateSession();
//        httpSecurity.authenticationProvider(authenticationProvider());
//        httpSecurity.addFilterBefore(new SessionAuthFilter(), UsernamePasswordAuthenticationFilter.class);
//        return httpSecurity.build();
//    }
}
