package com.example.demo.backend;

import com.yubico.webauthn.data.ByteArray;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * WebAuthn データアクセス層。
 *
 * <p>このクラスはバックエンドサーバーに配置される想定のデータアクセス処理を実装する。
 * 本デモではインメモリ実装だが、実際のプロジェクトではデータベースとREST APIに置き換わる。
 *
 * <p>【設計の前提】
 * <ul>
 *   <li>username: アプリケーション層の一意で不変な識別子（ユーザーがログイン時に入力）</li>
 *   <li>userHandle: WebAuthn層の一意で不変な識別子（サーバーが生成、プライバシー保護）</li>
 * </ul>
 *
 * <p>【相互参照の必要性】
 * <ul>
 *   <li>username → UserInfo: 登録・認証開始時に必要</li>
 *   <li>userHandle → UserInfo: 認証完了時に必要（WebAuthnプロトコルで使用）</li>
 *   <li>credentialId → AuthenticatorInfo → UserInfo: 認証時の署名検証に必要</li>
 * </ul>
 *
 * <p>【Yubicoライブラリとの関係】
 * このクラスはYubicoライブラリのCredentialRepositoryインターフェースを実装していない。
 * WebAuthnServiceがCredentialRepositoryを実装し、このクラスのメソッドを呼び出す設計。
 */
@Component
public class WebAuthnBackend {

    /**
     * 認証器の検証に必要な全データ。
     * 実際のバックエンドサーバーでは、1回のAPI呼び出し（データベースではJOIN）で取得される。
     */
    public static class CredentialData {
        public final byte[] credentialId;
        public final byte[] userHandle;
        public final byte[] publicKey;

        public CredentialData(byte[] credentialId, byte[] userHandle, byte[] publicKey) {
            this.credentialId = credentialId;
            this.userHandle = userHandle;
            this.publicKey = publicKey;
        }
    }

    private final ConcurrentHashMap<String, UserInfo> users = new ConcurrentHashMap<>();  // key: username
    private final ConcurrentHashMap<ByteArray, AuthenticatorInfo> authenticators = new ConcurrentHashMap<>();  // key: credentialId

    /**
     * usernameからUserInfoを取得する。
     */
    public Optional<UserInfo> findUserByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    /**
     * usernameからuserHandleを取得する。
     */
    public Optional<byte[]> findUserHandleByUsername(String username) {
        return Optional.ofNullable(users.get(username))
                .map(UserInfo::getUserHandle);
    }

    /**
     * userHandleからusernameを取得する。
     */
    public Optional<String> findUsernameByUserHandle(byte[] userHandle) {
        ByteArray targetHandle = new ByteArray(userHandle);
        return users.values().stream()
                .filter(user -> targetHandle.equals(new ByteArray(user.getUserHandle())))
                .map(UserInfo::getUsername)
                .findFirst();
    }

    /**
     * usernameに紐づくcredentialIdのリストを取得する。
     */
    public List<byte[]> findCredentialIdsByUsername(String username) {
        return Optional.ofNullable(users.get(username))
                .map(user -> user.getAuthenticators().stream()
                        .map(AuthenticatorInfo::getCredentialId)
                        .toList())
                .orElse(List.of());
    }

    /**
     * credentialIdとuserHandleから認証に必要な全データを取得する。
     * 実際のバックエンドサーバーでは、1回のAPI呼び出し（データベースではJOIN）で取得される。
     */
    public Optional<CredentialData> findCredentialData(byte[] credentialId, byte[] userHandle) {
        ByteArray credId = new ByteArray(credentialId);
        ByteArray targetHandle = new ByteArray(userHandle);

        return Optional.ofNullable(authenticators.get(credId))
                .filter(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return user != null && targetHandle.equals(new ByteArray(user.getUserHandle()));
                })
                .flatMap(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    if (user == null) {
                        return Optional.empty();
                    }
                    return Optional.of(new CredentialData(
                            auth.getCredentialId(),
                            user.getUserHandle(),
                            auth.getPublicKey()
                    ));
                });
    }

    /**
     * credentialIdとuserHandleからAuthenticatorInfoを取得する。
     */
    public Optional<AuthenticatorInfo> findAuthenticator(byte[] credentialId, byte[] userHandle) {
        ByteArray credId = new ByteArray(credentialId);
        ByteArray targetHandle = new ByteArray(userHandle);

        return Optional.ofNullable(authenticators.get(credId))
                .filter(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    return user != null && targetHandle.equals(new ByteArray(user.getUserHandle()));
                });
    }

    /**
     * credentialIdから認証に必要な全データを取得する（userHandle検証なし）。
     * 実際のバックエンドサーバーでは、1回のAPI呼び出し（データベースではJOIN）で取得される。
     */
    public Optional<CredentialData> findCredentialDataByCredentialId(byte[] credentialId) {
        return Optional.ofNullable(authenticators.get(new ByteArray(credentialId)))
                .flatMap(auth -> {
                    UserInfo user = users.get(auth.getUsername());
                    if (user == null) {
                        return Optional.empty();
                    }
                    return Optional.of(new CredentialData(
                            auth.getCredentialId(),
                            user.getUserHandle(),
                            auth.getPublicKey()
                    ));
                });
    }

    /**
     * credentialIdからAuthenticatorInfoを取得する（userHandle検証なし）。
     */
    public Optional<AuthenticatorInfo> findAuthenticatorByCredentialId(byte[] credentialId) {
        return Optional.ofNullable(authenticators.get(new ByteArray(credentialId)));
    }

    /**
     * UserInfoを保存する。
     */
    public void saveUser(UserInfo user) {
        users.put(user.getUsername(), user);
    }

    /**
     * AuthenticatorInfoを保存する。
     * ユーザーの認証器リストにも自動的に追加される。
     */
    public void saveAuthenticator(AuthenticatorInfo authenticator) {
        authenticators.put(new ByteArray(authenticator.getCredentialId()), authenticator);

        // ユーザーの認証器リストにも追加
        UserInfo user = users.get(authenticator.getUsername());
        if (user != null && user.getAuthenticators().stream()
                .noneMatch(a -> new ByteArray(a.getCredentialId()).equals(new ByteArray(authenticator.getCredentialId())))) {
            user.getAuthenticators().add(authenticator);
        }
    }
}
