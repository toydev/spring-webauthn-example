package com.example.demo.repository;

import com.example.demo.entity.Authenticator;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthenticatorRepository extends JpaRepository<Authenticator, Long> {
    Optional<Authenticator> findByCredentialId(byte[] credentialId);
}
