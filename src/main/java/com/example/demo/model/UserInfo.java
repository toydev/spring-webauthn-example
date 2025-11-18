package com.example.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
public class UserInfo {
    private String username;
    private String userHandle;  // Base64-encoded (32 bytes → 44 characters)
    private List<AuthenticatorInfo> authenticators;

    public UserInfo(String username, String userHandle) {
        this.username = username;
        this.userHandle = userHandle;
        this.authenticators = new ArrayList<>();
    }
}
