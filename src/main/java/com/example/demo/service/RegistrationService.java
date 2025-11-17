package com.example.demo.service;

import com.example.demo.entity.Authenticator;
import com.example.demo.entity.User;
import com.example.demo.repository.AuthenticatorRepository;
import com.example.demo.repository.UserRepository;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RegistrationService implements CredentialRepository {

    private final UserRepository userRepository;
    private final AuthenticatorRepository authenticatorRepository;

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> user.getAuthenticators().stream()
                        .map(auth -> PublicKeyCredentialDescriptor.builder()
                                .id(new ByteArray(auth.getCredentialId()))
                                .build())
                        .collect(Collectors.toSet()))
                .orElse(Set.of());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> new ByteArray(user.getUserHandle()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return userRepository.findByUserHandle(userHandle.getBytes())
                .map(User::getUsername);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return authenticatorRepository.findByCredentialId(credentialId.getBytes())
                .map(auth -> RegisteredCredential.builder()
                        .credentialId(new ByteArray(auth.getCredentialId()))
                        .userHandle(new ByteArray(auth.getUser().getUserHandle()))
                        .publicKeyCose(new ByteArray(auth.getPublicKey()))
                        .signatureCount(auth.getSignCount())
                        .build());
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return authenticatorRepository.findByCredentialId(credentialId.getBytes())
                .map(auth -> RegisteredCredential.builder()
                        .credentialId(new ByteArray(auth.getCredentialId()))
                        .userHandle(new ByteArray(auth.getUser().getUserHandle()))
                        .publicKeyCose(new ByteArray(auth.getPublicKey()))
                        .signatureCount(auth.getSignCount())
                        .build())
                .stream()
                .collect(Collectors.toSet());
    }

    @Transactional
    public void saveUser(User user) {
        userRepository.save(user);
    }

    @Transactional
    public void saveAuthenticator(Authenticator authenticator) {
        authenticatorRepository.save(authenticator);
    }

    @Transactional
    public void updateSignCount(ByteArray credentialId, long signCount) {
        authenticatorRepository.findByCredentialId(credentialId.getBytes())
                .ifPresent(auth -> {
                    auth.setSignCount(signCount);
                    authenticatorRepository.save(auth);
                });
    }
}
