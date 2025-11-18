package com.example.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
public class UserInfo {
    private String username;
    private byte[] userHandle;
    private List<AuthenticatorInfo> authenticators;

    public UserInfo(String username, byte[] userHandle) {
        this.username = username;
        this.userHandle = userHandle;
        this.authenticators = new ArrayList<>();
    }
}
