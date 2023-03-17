package com.example.cookie_session.controller;

import com.example.cookie_session.config.service.UserDetailsImpl;
import com.example.cookie_session.entities.Role;
import com.example.cookie_session.entities.User;
import com.example.cookie_session.payload.request.LoginRequest;
import com.example.cookie_session.payload.request.Signup;
import com.example.cookie_session.payload.response.UserResponse;
import com.example.cookie_session.repository.RoleRepository;
import com.example.cookie_session.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    UserRepository userRepository;


    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    HttpServletRequest request;

    @Autowired
    HttpServletResponse response;

    private SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        HttpSession session = request.getSession(true);
        session.setAttribute(session.getId(), userDetails);
        System.out.println(userDetails.getUsername());
        return ResponseEntity.ok(new UserResponse(
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

//    @PostMapping("/signin")
//    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
//        Authentication authentication = authenticationManager
//                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
//        System.out.println(authentication);
////        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
////        context.setAuthentication(authentication);
////        securityContextHolderStrategy.setContext(context);
////        securityContextRepository.saveContext(context, request, response);
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//        List<String> roles = userDetails.getAuthorities().stream()
//                .map(item -> item.getAuthority())
//                .collect(Collectors.toList());
////
//        HttpSession session = request.getSession(true);
//        session.setAttribute(session.getId(), userDetails);
//        System.out.println(userDetails.getUsername());
////        System.out.println("================" + session.getAttribute("username"));
////        Cookie[] cookies = request.getCookies();
////        for (Cookie c : cookies){
////            c.setAttribute("SessionId", session.getId());
////        }
////        Cookie c = new Cookie("SessionId", request.getSession().getId());
////        response.addCookie(c);
//        return ResponseEntity.ok(new UserResponse(
//                userDetails.getId(),
//                userDetails.getUsername(),
//                userDetails.getEmail(),
//                roles
////                c
//        ));
//    }

//    @GetMapping("/session")
//    public void testSession(HttpServletRequest request){
//        HttpSession session = request.getSession();
//        System.out.println("session: " +session);
////        System.out.println(session.getId());
//        byte[] bytes = session.getId().getBytes();
//        Cookie[] c = request.getCookies();
//        System.out.println("c: " + c);
//        for (Cookie cookie : c){
//            if (cookie.getValue().equals(Base64.getEncoder().encodeToString(bytes))){
//                System.out.println(session.getAttribute(session.getId()));
//                UserDetailsImpl userDetails = (UserDetailsImpl) session.getAttribute(session.getId());
//                System.out.println(userDetails.getUsername());
////                SecurityContext securityContext = (SecurityContext) session.getAttribute(session.getId());
////                System.out.println(securityContext.getAuthentication().getPrincipal());
//            }
//        }
//    }

    @PostMapping("/signup")
    public String registerUser(@RequestBody Signup signUpRequest) {
        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        strRoles.forEach(role -> {
            switch (role) {
                case "ROLE_ADMIN":
                    Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(adminRole);

                    break;
                case "ROLE_MODERATOR":
                    Role modRole = roleRepository.findByName("ROLE_MODERATOR")
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(modRole);

                    break;
                default:
                    Role userRole = roleRepository.findByName("ROLE_USER")
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(userRole);
            }
        });
        user.setRoles(roles);
        userRepository.save(user);

        return "User registered successfully!";
    }
}
