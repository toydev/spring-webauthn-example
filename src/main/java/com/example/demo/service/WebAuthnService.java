package com.example.demo.service;

import com.example.demo.model.AuthenticatorInfo;
import com.example.demo.model.UserInfo;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
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
    //
    // 【設計の前提】
    // - username: アプリケーション層の一意で不変な識別子（ユーザーがログイン時に入力）
    // - userHandle: WebAuthn層の一意で不変な識別子（サーバーが生成、プライバシー保護）
    //
    // 【相互参照の必要性】
    // - username → UserInfo: 登録・認証開始時に必要（ユーザーが入力するのはusername）
    // - userHandle → UserInfo: 認証完了時に必要（WebAuthnプロトコルで使用）
    // - credentialId → AuthenticatorInfo → UserInfo: 認証時の署名検証に必要
    //
    // 【現在の実装】
    // - users: username をキーとして高速アクセス
    // - authenticators: credentialId をキーとして高速アクセス
    // - AuthenticatorInfo.username: 逆引き用（credentialId → username → UserInfo）
    //
    private final ConcurrentHashMap<String, UserInfo> users = new ConcurrentHashMap<>();  // key: username
    private final ConcurrentHashMap<ByteArray, AuthenticatorInfo> authenticators = new ConcurrentHashMap<>();  // key: credentialId

    // ===== WebAuthn登録・認証フロー =====

    public PublicKeyCredentialCreationOptions startRegistration(String username) {
        ByteArray userHandle = getUserHandleForUsername(username)
                .orElseGet(() -> new ByteArray(generateUserHandle()));

        // displayName: 認証器の認証画面に表示されるユーザーの表示名
        // WebAuthn仕様で必須だが、本デモでは username をそのまま使用
        String displayName = username;

        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(displayName)
                .id(userHandle)
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
                        request.getUser().getId().getBytes()
                ));

        // 新規ユーザーの場合のみ保存
        if (user != null) {
            saveUser(user);
        }

        AuthenticatorInfo authenticator = new AuthenticatorInfo(
                result.getKeyId().getId().getBytes(),
                result.getPublicKeyCose().getBytes(),
                result.getAaguid().getBytes(),
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

        // 認証成功（特に追加処理なし）
    }

    // ===== CredentialRepository 実装（Yubicoライブラリが呼び出す） =====

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
                .filter(user -> userHandle.equals(new ByteArray(user.getUserHandle())))
                .map(UserInfo::getUsername)
                .findFirst();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return Optional.ofNullable(authenticators.get(credentialId))
                .filter(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return user != null && userHandle.equals(new ByteArray(user.getUserHandle()));
                })
                .map(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return RegisteredCredential.builder()
                            .credentialId(new ByteArray(auth.getCredentialId()))
                            .userHandle(new ByteArray(user.getUserHandle()))
                            .publicKeyCose(new ByteArray(auth.getPublicKey()))
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
        authenticators.put(new ByteArray(authenticator.getCredentialId()), authenticator);

        // ユーザーの認証器リストにも追加
        UserInfo user = users.get(authenticator.getUsername());
        if (user != null && user.getAuthenticators().stream()
                .noneMatch(a -> new ByteArray(a.getCredentialId()).equals(new ByteArray(authenticator.getCredentialId())))) {
            user.getAuthenticators().add(authenticator);
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
     * </ul>
     *
     * @return 32バイトのランダムなユーザーハンドル
     */
    private byte[] generateUserHandle() {
        byte[] handle = new byte[32];
        random.nextBytes(handle);
        return handle;
    }
}
