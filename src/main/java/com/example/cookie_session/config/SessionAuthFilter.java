package com.example.cookie_session.config;

import com.example.cookie_session.config.service.UserDetailsImpl;
import com.example.cookie_session.config.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;
public class SessionAuthFilter extends OncePerRequestFilter {

    public SessionAuthFilter(UserDetailsServiceImpl userDetailsService){
        this.userDetailsService = userDetailsService;
    }

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(SessionAuthFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if ("/api/auth/signin".equals(request.getServletPath())){
            filterChain.doFilter(request,response);
            return;
        }
//        HttpSession session = request.getSession();
//        System.out.println("session: " +session);
//        byte[] bytes = session.getId().getBytes("UTF-8");
//        System.out.println("bytes: " + bytes);
//        System.out.println("Encoded: " + Base64.getEncoder().encodeToString(bytes));
//        Cookie[] c = request.getCookies();
//        System.out.println("c: " + c);
//        for (Cookie cookie : c){
//            if (cookie.getValue().equals(Base64.getEncoder().encodeToString(bytes))){
//                System.out.println(session.getAttribute(session.getId()));
////                SecurityContext securityContext = (SecurityContext) session.getAttribute(session.getId());
////                System.out.println(securityContext.getAuthentication().getPrincipal());
//            }
//        }

        HttpSession session = request.getSession();
//        System.out.println("session: " +session);
        byte[] bytes = session.getId().getBytes("UTF-8");
//        System.out.println("bytes: " + bytes);
        System.out.println("Encoded: " + Base64.getEncoder().encodeToString(bytes));
        Cookie[] c = request.getCookies();
//        System.out.println("c: " + c);
        for (Cookie cookie : c){
            if (cookie.getValue().equals(Base64.getEncoder().encodeToString(bytes))){
//                System.out.println(session.getAttribute(session.getId()));
//                SecurityContext securityContext = (SecurityContext) session.getAttribute(session.getId());
//                System.out.println(securityContext.getAuthentication().getPrincipal());
                UserDetailsImpl userDetails = (UserDetailsImpl) session.getAttribute(session.getId());
                System.out.println(userDetails.getUsername());
                UserDetails userDetails1 = userDetailsService.loadUserByUsername(userDetails.getUsername());
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails1,
                                null,
                                userDetails1.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request,response);
    }
}
