package com.example.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthenticatorInfo {
    private String credentialId;  // Base64-encoded
    private String publicKey;     // Base64-encoded
    private long signCount;
    private String aaguid;        // Base64-encoded
    private String username;
}
