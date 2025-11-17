package com.example.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthenticatorInfo {
    private byte[] credentialId;
    private byte[] publicKey;
    private long signCount;
    private byte[] aaguid;
    private String username;
}
