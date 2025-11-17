package com.example.demo.service;

import com.example.demo.model.AuthenticatorInfo;
import com.example.demo.model.UserInfo;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class WebAuthnService {

    private final RelyingParty relyingParty;
    private final RegistrationService registrationService;
    private final SecureRandom random;

    public PublicKeyCredentialCreationOptions startRegistration(String username, String displayName) {
        // 既存ユーザーの userHandle を取得、なければ新規生成
        byte[] userHandle = registrationService.getUserHandleForUsername(username)
                .map(ByteArray::getBytes)
                .orElseGet(() -> {
                    byte[] newHandle = new byte[32];
                    random.nextBytes(newHandle);
                    return newHandle;
                });

        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(displayName)
                .id(new ByteArray(userHandle))
                .build();

        StartRegistrationOptions options = StartRegistrationOptions.builder()
                .user(userIdentity)
                .timeout(120000L)
                .build();

        return relyingParty.startRegistration(options);
    }

    public void finishRegistration(String username, String displayName,
                                   PublicKeyCredentialCreationOptions request,
                                   PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential)
            throws RegistrationFailedException {

        FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                .request(request)
                .response(credential)
                .build();

        RegistrationResult result = relyingParty.finishRegistration(options);

        // 既存ユーザーがいなければ新規作成
        UserInfo user = registrationService.getUserHandleForUsername(username)
                .map(userHandle -> {
                    // 既存ユーザーは既に保存されているのでそのまま使う
                    // ここでは何もしない（認証器だけ追加）
                    return (UserInfo) null;
                })
                .orElseGet(() -> new UserInfo(username, displayName, request.getUser().getId().getBytes()));

        // 新規ユーザーの場合のみ保存
        if (user != null) {
            registrationService.saveUser(user);
        }

        AuthenticatorInfo authenticator = new AuthenticatorInfo(
                result.getKeyId().getId().getBytes(),
                result.getPublicKeyCose().getBytes(),
                result.getSignatureCount(),
                result.getAaguid().getBytes(),
                username
        );

        registrationService.saveAuthenticator(authenticator);
    }

    public AssertionRequest startAuthentication(String username) {
        StartAssertionOptions options = StartAssertionOptions.builder()
                .username(username)
                .build();

        return relyingParty.startAssertion(options);
    }

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
