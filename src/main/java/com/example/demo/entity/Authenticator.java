package com.example.demo.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "authenticators")
@Data
@NoArgsConstructor
public class Authenticator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private byte[] credentialId;

    @Column(nullable = false, length = 1024)
    private byte[] publicKey;

    @Column(nullable = false)
    private Long signCount;

    @Column
    private byte[] aaguid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public Authenticator(byte[] credentialId, byte[] publicKey, Long signCount, byte[] aaguid, User user) {
        this.credentialId = credentialId;
        this.publicKey = publicKey;
        this.signCount = signCount;
        this.aaguid = aaguid;
        this.user = user;
    }
}
