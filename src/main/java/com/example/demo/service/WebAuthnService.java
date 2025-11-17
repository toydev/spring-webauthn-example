package com.example.demo.service;

import com.example.demo.entity.Authenticator;
import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class WebAuthnService {

    private final RelyingParty relyingParty;
    private final RegistrationService registrationService;
    private final UserRepository userRepository;
    private final SecureRandom random = new SecureRandom();

    public PublicKeyCredentialCreationOptions startRegistration(String username, String displayName) {
        byte[] userHandle = new byte[32];
        random.nextBytes(userHandle);

        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(displayName)
                .id(new ByteArray(userHandle))
                .build();

        // シンプルな設定：どの認証器でも許可
        StartRegistrationOptions options = StartRegistrationOptions.builder()
                .user(userIdentity)
                .timeout(120000L)
                .build();

        return relyingParty.startRegistration(options);
    }

    @Transactional
    public void finishRegistration(String username, String displayName,
                                   PublicKeyCredentialCreationOptions request,
                                   PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential)
            throws RegistrationFailedException {

        FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                .request(request)
                .response(credential)
                .build();

        RegistrationResult result = relyingParty.finishRegistration(options);

        User user = userRepository.findByUsername(username)
                .orElseGet(() -> {
                    User newUser = new User(username, displayName, request.getUser().getId().getBytes());
                    return newUser;
                });

        Authenticator authenticator = new Authenticator(
                result.getKeyId().getId().getBytes(),
                result.getPublicKeyCose().getBytes(),
                result.getSignatureCount(),
                result.getAaguid().getBytes(),
                user
        );

        user.getAuthenticators().add(authenticator);
        registrationService.saveUser(user);
    }

    public AssertionRequest startAuthentication(String username) {
        StartAssertionOptions options = StartAssertionOptions.builder()
                .username(username)
                .build();

        return relyingParty.startAssertion(options);
    }

    @Transactional
    public void finishAuthentication(AssertionRequest request,
                                     PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential)
            throws AssertionFailedException {

        FinishAssertionOptions options = FinishAssertionOptions.builder()
                .request(request)
                .response(credential)
                .build();

        AssertionResult result = relyingParty.finishAssertion(options);

        if (result.isSuccess()) {
            registrationService.updateSignCount(
                    result.getCredentialId(),
                    result.getSignatureCount()
            );
        }
    }
}
