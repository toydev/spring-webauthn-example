package com.example.demo.backend;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * WebAuthn認証器の情報。
 *
 * <p>【UserInfo との相互参照】
 * - UserInfo → List&lt;AuthenticatorInfo&gt;: ユーザーの認証器一覧
 * - AuthenticatorInfo.username → UserInfo: 認証時の逆引き
 *
 * <p>【前提】username は一意で不変な識別子
 */
@Data
@AllArgsConstructor
public class AuthenticatorInfo {
    private byte[] credentialId;  // 必須：認証時に使用する鍵を特定（長さは認証器依存で可変）
    private byte[] publicKey;     // 必須：署名検証に使用する公開鍵（COSE形式、長さはアルゴリズム依存）
    private byte[] aaguid;        // 任意：認証器モデルのUUID（16バイト固定、FIDO MDS参照で名前取得可）
    private String username;      // 必須：credentialId → UserInfo の逆引き用
}
