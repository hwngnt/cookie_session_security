package com.example.cookie_session.payload.request;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class Signup {
    private String username;
    private String password;
    private String email;
    private Set<String> role;
}

