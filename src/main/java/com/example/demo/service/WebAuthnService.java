package com.example.demo.service;

import com.example.demo.model.AuthenticatorInfo;
import com.example.demo.model.UserInfo;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class WebAuthnService implements CredentialRepository {

    private final RelyingParty relyingParty;
    private final SecureRandom random;

    public WebAuthnService() {
        this.random = new SecureRandom();

        // RelyingParty の設定
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id("localhost")
                .name("WebAuthn Demo")
                .build();

        this.relyingParty = RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(this)
                .origins(Set.of("http://localhost:8080"))
                .build();
    }

    // ===== データストレージ（インメモリ） =====
    private final ConcurrentHashMap<String, UserInfo> users = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AuthenticatorInfo> authenticators = new ConcurrentHashMap<>();  // key: Base64-encoded credentialId

    // ===== WebAuthn登録・認証フロー =====

    public PublicKeyCredentialCreationOptions startRegistration(String username) {
        byte[] userHandle = getUserHandleForUsername(username)
                .map(ByteArray::getBytes)
                .orElseGet(() -> Base64.getDecoder().decode(generateUserHandle()));

        // displayName: 認証器の認証画面に表示されるユーザーの表示名
        // WebAuthn仕様で必須だが、本デモでは username をそのまま使用
        String displayName = username;

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

    public void finishRegistration(String username,
                                   PublicKeyCredentialCreationOptions request,
                                   PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential)
            throws RegistrationFailedException {

        FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                .request(request)
                .response(credential)
                .build();

        RegistrationResult result = relyingParty.finishRegistration(options);

        // 既存ユーザーがいなければ新規作成
        UserInfo user = getUserHandleForUsername(username)
                .map(userHandle -> {
                    // 既存ユーザーは既に保存されているのでそのまま使う
                    // ここでは何もしない（認証器だけ追加）
                    return (UserInfo) null;
                })
                .orElseGet(() -> new UserInfo(
                        username,
                        Base64.getEncoder().encodeToString(request.getUser().getId().getBytes())
                ));

        // 新規ユーザーの場合のみ保存
        if (user != null) {
            saveUser(user);
        }

        AuthenticatorInfo authenticator = new AuthenticatorInfo(
                Base64.getEncoder().encodeToString(result.getKeyId().getId().getBytes()),
                Base64.getEncoder().encodeToString(result.getPublicKeyCose().getBytes()),
                result.getSignatureCount(),
                Base64.getEncoder().encodeToString(result.getAaguid().getBytes()),
                username
        );

        saveAuthenticator(authenticator);
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
            updateSignCount(
                    result.getCredentialId(),
                    result.getSignatureCount()
            );
        }
    }

    // ===== CredentialRepository 実装（Yubicoライブラリが呼び出す） =====

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return Optional.ofNullable(users.get(username))
                .map(user -> user.getAuthenticators().stream()
                        .map(auth -> PublicKeyCredentialDescriptor.builder()
                                .id(new ByteArray(Base64.getDecoder().decode(auth.getCredentialId())))
                                .build())
                        .collect(Collectors.toSet()))
                .orElse(Set.of());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return Optional.ofNullable(users.get(username))
                .map(user -> new ByteArray(Base64.getDecoder().decode(user.getUserHandle())));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        String userHandleBase64 = Base64.getEncoder().encodeToString(userHandle.getBytes());
        return users.values().stream()
                .filter(user -> user.getUserHandle().equals(userHandleBase64))
                .map(UserInfo::getUsername)
                .findFirst();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        String credentialIdBase64 = Base64.getEncoder().encodeToString(credentialId.getBytes());
        String userHandleBase64 = Base64.getEncoder().encodeToString(userHandle.getBytes());

        return Optional.ofNullable(authenticators.get(credentialIdBase64))
                .filter(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return user != null && user.getUserHandle().equals(userHandleBase64);
                })
                .map(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return RegisteredCredential.builder()
                            .credentialId(new ByteArray(Base64.getDecoder().decode(auth.getCredentialId())))
                            .userHandle(new ByteArray(Base64.getDecoder().decode(user.getUserHandle())))
                            .publicKeyCose(new ByteArray(Base64.getDecoder().decode(auth.getPublicKey())))
                            .signatureCount(auth.getSignCount())
                            .build();
                });
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        String credentialIdBase64 = Base64.getEncoder().encodeToString(credentialId.getBytes());

        return Optional.ofNullable(authenticators.get(credentialIdBase64))
                .map(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return RegisteredCredential.builder()
                            .credentialId(new ByteArray(Base64.getDecoder().decode(auth.getCredentialId())))
                            .userHandle(new ByteArray(Base64.getDecoder().decode(user.getUserHandle())))
                            .publicKeyCose(new ByteArray(Base64.getDecoder().decode(auth.getPublicKey())))
                            .signatureCount(auth.getSignCount())
                            .build();
                })
                .stream()
                .collect(Collectors.toSet());
    }

    // ===== データ保存・更新 =====

    private void saveUser(UserInfo user) {
        users.put(user.getUsername(), user);
    }

    private void saveAuthenticator(AuthenticatorInfo authenticator) {
        authenticators.put(authenticator.getCredentialId(), authenticator);

        // ユーザーの認証器リストにも追加
        UserInfo user = users.get(authenticator.getUsername());
        if (user != null && user.getAuthenticators().stream()
                .noneMatch(a -> a.getCredentialId().equals(authenticator.getCredentialId()))) {
            user.getAuthenticators().add(authenticator);
        }
    }

    private void updateSignCount(ByteArray credentialId, long signCount) {
        String credentialIdBase64 = Base64.getEncoder().encodeToString(credentialId.getBytes());
        AuthenticatorInfo auth = authenticators.get(credentialIdBase64);
        if (auth != null) {
            auth.setSignCount(signCount);
        }
    }

    // ===== ヘルパーメソッド =====

    /**
     * userHandle (user.id) を生成する。
     *
     * <p>WebAuthn仕様におけるユーザー識別子で、以下の特性を持つ：
     * <ul>
     *   <li>ユーザー識別情報を含めてはいけない（プライバシー保護のため）</li>
     *   <li>仕様上64バイト未満のユニーク値であること</li>
     *   <li>本実装では32バイトの乱数を使用（衝突確率は約 1/2^256 ≈ 10^-77 で天文学的に低い）</li>
     *   <li>実プロジェクトではデータベースのUNIQUE制約で万が一の衝突を検出することを推奨</li>
     *   <li>Base64エンコード後は44文字（データベースではVARCHAR(44)で格納可能）</li>
     * </ul>
     *
     * @return Base64エンコードされたユーザーハンドル（44文字）
     */
    private String generateUserHandle() {
        byte[] handle = new byte[32];
        random.nextBytes(handle);
        return Base64.getEncoder().encodeToString(handle);
    }
}
