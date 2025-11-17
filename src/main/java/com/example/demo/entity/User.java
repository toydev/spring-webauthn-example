package com.example.demo.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String displayName;

    @Column(unique = true, nullable = false)
    private byte[] userHandle;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Authenticator> authenticators = new ArrayList<>();

    public User(String username, String displayName, byte[] userHandle) {
        this.username = username;
        this.displayName = displayName;
        this.userHandle = userHandle;
    }
}
