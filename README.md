# WebAuthn デモプロジェクト

WebAuthn（Web Authentication API）の本質を理解するための段階的なデモ集です。

## プロジェクト構成

このリポジトリには、学習の進行度に応じた2つの独立したデモが含まれています：

### 📌 [demo1-basic](./demo1-basic/) - WebAuthn の本質

**目的**: WebAuthn APIの最小限の実装を通じて、本質的な仕組みを理解する

**含まれる機能**:
- ✅ ユーザー登録（Registration）
- ✅ 認証（Authentication）

**含まれない機能**:
- ❌ セッション管理
- ❌ 認証器の一覧表示
- ❌ 認証器の削除
- ❌ デバイス名の設定

**ポイント**: WebAuthn仕様で定義されているコア機能のみを実装。アプリケーション層の機能は一切含めていません。

---

### 📌 [demo2-management](./demo2-management/) - 認証器管理

**目的**: 実用的なWebAuthnアプリケーションの実装パターンを学ぶ

**含まれる機能**:
- ✅ ユーザー登録（Registration）
- ✅ 認証（Authentication）
- ✅ セッション管理
- ✅ 認証器の一覧表示
- ✅ 認証器の削除
- ✅ **デバイス名の設定・表示**
- ✅ 複数認証器の管理

**ポイント**: GoogleやGitHubなどの実サービスに近い実装。WebAuthn仕様と、アプリケーション層の機能の違いを明確に理解できます。

---

## 技術スタック

### バックエンド
- **Spring Boot 3.3.4** + Java 21
- **Yubico webauthn-server-core 2.7.0** (WebAuthn Relying Party 実装)
- インメモリデータベース（デモ用）

### フロントエンド
- Vanilla JavaScript（ライブラリ不使用）
- WebAuthn API直接呼び出し
- Thymeleaf（サーバーサイドテンプレート）

---

## 開発環境

### 必須
- Java 21以降
- Maven 3.6以降

### 推奨
- Eclipse（各プロジェクトは独立したEclipseプロジェクトとしてインポート可能）

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

## 学習の進め方

### 1. demo1-basicから始める

まずは最小限の実装でWebAuthnの流れを理解しましょう：

1. ユーザー登録フローを実際に試す
2. 認証フローを試す
3. ブラウザの開発者ツールでネットワーク通信を観察する
4. バックエンドのコードを読む（特に`WebAuthnService.java`）

**重要なポイント**:
- `PublicKeyCredentialCreationOptions` の構造
- `challenge` の役割（リプレイ攻撃対策）
- `userHandle` と `username` の違い
- 公開鍵暗号による署名検証の流れ

### 2. demo2-managementで実用パターンを学ぶ

次に、実用的なアプリケーションの実装を学びましょう：

1. セッション管理の実装方法
2. 複数認証器の管理
3. デバイス名などのメタデータ管理
4. WebAuthn仕様とアプリケーション層の責任分離

**比較してみよう**:
- demo1-basicとdemo2-managementのコードを見比べる
- どの機能がWebAuthn仕様で、どれがアプリケーション層か区別する

---

## プロジェクトの設計思想

### シンプルさを最優先

- 不要な抽象化を排除
- WebAuthnの本質に集中
- 理解しやすく、学習しやすいコード

### ポータビリティ

- 実プロジェクトへの転用が容易
- グローバルな設定に依存しない
- WebAuthn固有の処理を局所化

### 本質の理解

- WebAuthn仕様の理解が深まる実装
- ライブラリの正しい使い方を示す
- 動作する最小限のコード

詳細は [.claude/CLAUDE.md](./.claude/CLAUDE.md) を参照してください。

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
│   │           └── webauthn.js                 # WebAuthn クライアント実装
│   └── test/
└── pom.xml
```

---

## 参考資料

- [W3C WebAuthn仕様](https://www.w3.org/TR/webauthn-2/)
- [Yubico webauthn-server-core](https://github.com/Yubico/java-webauthn-server)
- [MDN Web Authentication API](https://developer.mozilla.org/ja/docs/Web/API/Web_Authentication_API)
- [WebAuthn.io](https://webauthn.io/) - インタラクティブデモ

---

## ライセンス

このデモプロジェクトはMITライセンスで公開されています。

---

## 貢献

このプロジェクトは学習目的のデモです。Issue や Pull Request は歓迎します。
