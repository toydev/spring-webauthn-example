# WebAuthn デモプロジェクト

WebAuthnをSpring Bootアプリケーションに組み込むための実装サンプルです。

## WebAuthnとは

WebAuthnの本質は、**認証器によるcredentialの登録とそれを使った認証**です。
認証器はデバイス（PC、スマートフォン、物理セキュリティキーなど）に搭載されており、
Windows Hello、Touch ID/Face ID、YubiKeyなどの形で提供されます。

- デバイス側とサーバ側がcredentialを対で持ち、署名検証が成功することで認証が成立します
- デバイス側: 秘密鍵（デバイス内に保管）
- サーバ側: 公開鍵、Credential ID（データベースに保管）

credentialの削除はWebAuthn仕様の範疇外です。
デバイス側ではOS/ブラウザの設定から、サーバ側では単にデータベースから公開鍵とCredential IDを消すだけの操作になります。

## WebAuthn実装における責任分担

WebAuthnの実装では、以下の3つの層がそれぞれ異なる責任を持ちます。

### 1. OS/ブラウザが提供

クライアント側のデバイス認証機能とUIは、OS・ブラウザに組み込まれています。

- 実装: `navigator.credentials.create()` / `navigator.credentials.get()` を呼ぶだけ
- 役割: 指紋認証、顔認証、セキュリティキーなどのデバイス認証処理と画面表示
- カスタマイズ: UIのデザイン・動作は変更不可。調整できるのはAPIパラメータのみ
- ブラウザサポート状況: [Can I use - Web Authentication API](https://caniuse.com/webauthn)

### 2. Yubico webauthn-server-core が提供

サーバ側のWebAuthn処理を担う汎用ライブラリです。Webフレームワークやストレージの種類に依存しません。

- リクエストデータの生成: 登録・認証開始時にクライアントへ送信するデータを生成
- 応答の検証: クライアントから受け取った署名などを検証
- 通信データの定義: サーバ・クライアント間のリクエスト/レスポンス構造

### 3. 開発者が実装する必要があるもの

Yubico webauthn-server-coreは汎用ライブラリのため、以下は自分で実装します。

- credentialの保管: 公開鍵、Credential ID、ユーザー情報などの永続化
- Webフレームワークへの統合: REST APIエンドポイント、セッション管理など

このデモでは、Spring Bootへの統合例とcredentialの保管実装（インメモリDB）を提供しています。

---

## プロジェクト構成

このリポジトリには、段階的に理解できる2つの独立したデモが含まれています。

### demo1-basic - WebAuthnのコア機能のみ

WebAuthn仕様で定義されているコア機能のみを実装。

含まれる機能:
- ユーザー登録（Registration）
- 認証（Authentication）

含まれない機能:
- セッション管理（アプリケーション層の機能）
- 認証器の一覧表示・削除（アプリケーション層の機能）
- デバイス名管理（アプリケーション層の機能）

### demo2-management - 実用的な実装

実際のサービスで必要となる認証器管理機能を含む実装。

含まれる機能:
- ユーザー登録（Registration）
- 認証（Authentication）
- セッション管理
- 認証器の一覧表示
- 認証器の削除
- デバイス名の設定・表示
- 複数認証器の管理

demo1とdemo2を比較することで、WebAuthn仕様とアプリケーション層の責任分離を理解できます。

---

## 技術スタック

### バックエンド
- Spring Boot 3.3.4 + Java 21
- Yubico webauthn-server-core 2.7.0 - WebAuthn Relying Party実装
- インメモリデータベース（デモ用）

### フロントエンド
- Vanilla JavaScript（ライブラリ不使用）
- Web Authentication API
- Thymeleaf

---

## 開発環境

- Java 21以降
- Maven 3.6以降

---

## 実行方法

各デモは独立したSpring Bootアプリケーションです。

### demo1-basicを実行

```bash
cd demo1-basic
./mvnw spring-boot:run
```

ブラウザで http://localhost:8080 を開く

### demo2-managementを実行

```bash
cd demo2-management
./mvnw spring-boot:run
```

ブラウザで http://localhost:8080 を開く

---

## コード構成

各デモプロジェクトは以下の構成です：

```
demo1-basic/ または demo2-management/
├── src/
│   ├── main/
│   │   ├── java/com/example/demo/
│   │   │   ├── controller/
│   │   │   │   └── WebAuthnController.java    # REST API + 画面表示
│   │   │   ├── service/
│   │   │   │   └── WebAuthnService.java       # WebAuthn ビジネスロジック
│   │   │   ├── backend/
│   │   │   │   ├── WebAuthnBackend.java       # データアクセス層
│   │   │   │   ├── UserInfo.java              # ユーザー情報
│   │   │   │   └── AuthenticatorInfo.java     # 認証器情報
│   │   │   └── DemoApplication.java
│   │   └── resources/
│   │       ├── templates/
│   │       │   └── index.html                  # Thymeleafテンプレート
│   │       └── static/
│   │           ├── style.css                   # スタイルシート
│   │           └── webauthn.js                 # WebAuthn クライアント実装
│   └── test/
└── pom.xml
```

---

## 参考資料

- [W3C WebAuthn仕様](https://www.w3.org/TR/webauthn-2/)
- [Yubico webauthn-server-core](https://github.com/Yubico/java-webauthn-server)
- [MDN Web Authentication API](https://developer.mozilla.org/ja/docs/Web/API/Web_Authentication_API)
- [Can I use - Web Authentication API](https://caniuse.com/webauthn)
- [WebAuthn.io](https://webauthn.io/) - インタラクティブデモ

---

## ライセンス

このデモプロジェクトはMITライセンスで公開されています。
