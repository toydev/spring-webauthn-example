package com.example.demo.service;

import com.example.demo.model.AuthenticatorInfo;
import com.example.demo.model.UserInfo;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class RegistrationService implements CredentialRepository {

    private final ConcurrentHashMap<String, UserInfo> users = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<ByteArray, AuthenticatorInfo> authenticators = new ConcurrentHashMap<>();

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return Optional.ofNullable(users.get(username))
                .map(user -> user.getAuthenticators().stream()
                        .map(auth -> PublicKeyCredentialDescriptor.builder()
                                .id(new ByteArray(auth.getCredentialId()))
                                .build())
                        .collect(Collectors.toSet()))
                .orElse(Set.of());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return Optional.ofNullable(users.get(username))
                .map(user -> new ByteArray(user.getUserHandle()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return users.values().stream()
                .filter(user -> Arrays.equals(user.getUserHandle(), userHandle.getBytes()))
                .map(UserInfo::getUsername)
                .findFirst();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return Optional.ofNullable(authenticators.get(credentialId))
                .filter(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return user != null && Arrays.equals(user.getUserHandle(), userHandle.getBytes());
                })
                .map(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return RegisteredCredential.builder()
                            .credentialId(new ByteArray(auth.getCredentialId()))
                            .userHandle(new ByteArray(user.getUserHandle()))
                            .publicKeyCose(new ByteArray(auth.getPublicKey()))
                            .signatureCount(auth.getSignCount())
                            .build();
                });
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return Optional.ofNullable(authenticators.get(credentialId))
                .map(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return RegisteredCredential.builder()
                            .credentialId(new ByteArray(auth.getCredentialId()))
                            .userHandle(new ByteArray(user.getUserHandle()))
                            .publicKeyCose(new ByteArray(auth.getPublicKey()))
                            .signatureCount(auth.getSignCount())
                            .build();
                })
                .stream()
                .collect(Collectors.toSet());
    }

    public void saveUser(UserInfo user) {
        users.put(user.getUsername(), user);
    }

    public void saveAuthenticator(AuthenticatorInfo authenticator) {
        authenticators.put(new ByteArray(authenticator.getCredentialId()), authenticator);

        // ユーザーの認証器リストにも追加
        UserInfo user = users.get(authenticator.getUsername());
        if (user != null && user.getAuthenticators().stream()
                .noneMatch(a -> Arrays.equals(a.getCredentialId(), authenticator.getCredentialId()))) {
            user.getAuthenticators().add(authenticator);
        }
    }

    public void updateSignCount(ByteArray credentialId, long signCount) {
        AuthenticatorInfo auth = authenticators.get(credentialId);
        if (auth != null) {
            auth.setSignCount(signCount);
        }
    }
}
