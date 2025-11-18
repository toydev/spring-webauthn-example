package com.example.demo.backend;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * WebAuthnユーザー情報。
 *
 * <p>【識別子の役割】
 * <ul>
 *   <li>username: アプリケーション層の一意で不変な識別子（ユーザーが知っている・入力する）</li>
 *   <li>userHandle: WebAuthn層の一意で不変な識別子（32バイトのランダム値、プライバシー保護）</li>
 * </ul>
 *
 * <p>【認証器との関係】
 * 1人のユーザーが複数の認証器を登録可能（例：Windows Hello + YubiKey）
 */
@Data
@AllArgsConstructor
public class UserInfo {
    private String username;              // アプリケーション層の識別子（一意・不変）
    private byte[] userHandle;            // WebAuthn層の識別子（32バイトのランダム値）
    private List<AuthenticatorInfo> authenticators;  // このユーザーに紐づく認証器一覧

    public UserInfo(String username, byte[] userHandle) {
        this.username = username;
        this.userHandle = userHandle;
        this.authenticators = new ArrayList<>();
    }
}
