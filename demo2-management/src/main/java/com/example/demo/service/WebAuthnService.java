package com.example.demo.service;

import com.example.demo.backend.AuthenticatorInfo;
import com.example.demo.backend.UserInfo;
import com.example.demo.backend.WebAuthnBackend;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class WebAuthnService implements CredentialRepository {

    private final RelyingParty relyingParty;
    private final SecureRandom random;
    private final WebAuthnBackend backend;

    public WebAuthnService(WebAuthnBackend backend) {
        this.backend = backend;
        this.random = new SecureRandom();

        // ===== 認証依頼側（このサーバーアプリケーション）の設定 =====
        //
        // RelyingPartyIdentity: このアプリケーション自体の識別情報
        //
        // - id: RP ID（通常はドメイン名、本番環境なら "example.com" など）
        //   認証器が生成する credentialId はこの RP ID に紐付けられる（フィッシング対策）
        //   【重要】origins のホスト部分と一致する必要がある
        //   例: id="localhost" → origins="http://localhost:8080"
        //
        // - name: 認証器の画面に表示される人間が読める名前
        //   認証器によっては表示されない場合もある（Windows Hello では表示されない）
        //
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

    // ===== WebAuthn登録・認証フロー =====

    /**
     * 登録開始: クライアントに送信する認証器登録オプションを生成する
     */
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

    /**
     * 登録完了: クライアントから受け取った認証器情報を検証・保存する
     */
    public void finishRegistration(String username,
                                   PublicKeyCredentialCreationOptions request,
                                   PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential,
                                   String nickname)
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
            backend.saveUser(user);
        }

        AuthenticatorInfo authenticator = new AuthenticatorInfo(
                result.getKeyId().getId().getBytes(),
                result.getPublicKeyCose().getBytes(),
                result.getAaguid().getBytes(),
                username,
                nickname  // アプリケーション層の機能：ユーザーが設定した認証器の表示名
        );

        backend.saveAuthenticator(authenticator);
    }

    /**
     * 認証開始: クライアントに送信する認証オプションを生成する
     */
    public AssertionRequest startAuthentication(String username) {
        StartAssertionOptions options = StartAssertionOptions.builder()
                .username(username)
                .build();

        return relyingParty.startAssertion(options);
    }

    /**
     * 認証完了: クライアントから受け取った署名を検証し、認証されたユーザー名を返す
     */
    public String finishAuthentication(AssertionRequest request,
                                       PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential)
            throws AssertionFailedException {

        FinishAssertionOptions options = FinishAssertionOptions.builder()
                .request(request)
                .response(credential)
                .build();

        AssertionResult result = relyingParty.finishAssertion(options);

        // 認証されたユーザー名を返す
        return result.getUsername();
    }

    // ===== CredentialRepository 実装（Yubicoライブラリが呼び出す） =====
    //
    // WebAuthnServiceはYubicoライブラリのCredentialRepositoryインターフェースを実装している。
    // Yubicoライブラリから呼び出されるため、このクラスに実装を保持する必要がある。
    // データアクセスはWebAuthnBackend経由で行う。

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        List<byte[]> credentialIds = backend.findCredentialIdsByUsername(username);
        return credentialIds.stream()
                .map(credId -> PublicKeyCredentialDescriptor.builder()
                        .id(new ByteArray(credId))
                        .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return backend.findUserHandleByUsername(username)
                .map(ByteArray::new);
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return backend.findUsernameByUserHandle(userHandle.getBytes());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return backend.findCredentialData(credentialId.getBytes(), userHandle.getBytes())
                .map(data -> RegisteredCredential.builder()
                        .credentialId(new ByteArray(data.credentialId))
                        .userHandle(new ByteArray(data.userHandle))
                        .publicKeyCose(new ByteArray(data.publicKey))
                        .build());
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return backend.findCredentialDataByCredentialId(credentialId.getBytes())
                .map(data -> RegisteredCredential.builder()
                        .credentialId(new ByteArray(data.credentialId))
                        .userHandle(new ByteArray(data.userHandle))
                        .publicKeyCose(new ByteArray(data.publicKey))
                        .build())
                .stream()
                .collect(Collectors.toSet());
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
