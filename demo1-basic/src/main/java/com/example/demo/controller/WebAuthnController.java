package com.example.demo.controller;

import com.example.demo.service.WebAuthnService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.servlet.http.HttpSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * WebAuthn デモ - 基本実装
 *
 * <p>このコントローラーはWebAuthnの本質的な機能のみを実装しています：
 * <ul>
 *   <li>新規ユーザー登録（Registration）</li>
 *   <li>認証（Authentication）</li>
 * </ul>
 *
 * <p>セッション管理、認証器一覧表示、削除などのアプリケーション層の機能は含まれていません。
 */
@Controller
@RequiredArgsConstructor
public class WebAuthnController {

    private final WebAuthnService webAuthnService;

    private static final String REGISTRATION_REQUEST_KEY = "webauthn.registration.request";
    private static final String ASSERTION_REQUEST_KEY = "webauthn.assertion.request";

    // ===== 画面表示 =====

    @GetMapping("/")
    public String index() {
        return "index";
    }

    // ===== WebAuthn API =====

    /**
     * 登録開始: チャレンジとオプションを生成してクライアントに返す
     */
    @PostMapping("/api/webauthn/register/start")
    @ResponseBody
    public ResponseEntity<String> startRegistration(@RequestBody RegistrationStartRequest request, HttpSession session) {
        try {
            PublicKeyCredentialCreationOptions options =
                    webAuthnService.startRegistration(request.getUsername());

            // チャレンジを検証するため、セッションに保存
            session.setAttribute(REGISTRATION_REQUEST_KEY, options);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(options.toJson());
        } catch (JsonProcessingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to serialize registration options\"}");
        }
    }

    /**
     * 登録完了: クライアントから受け取った認証器情報を検証・保存
     */
    @PostMapping("/api/webauthn/register/finish")
    @ResponseBody
    public ResponseEntity<?> finishRegistration(@RequestBody RegistrationFinishRequest request, HttpSession session) {
        try {
            PublicKeyCredentialCreationOptions options =
                    (PublicKeyCredentialCreationOptions) session.getAttribute(REGISTRATION_REQUEST_KEY);
            if (options == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "No registration in progress"));
            }

            webAuthnService.finishRegistration(
                    request.getUsername(),
                    options,
                    request.getCredential()
            );

            session.removeAttribute(REGISTRATION_REQUEST_KEY);
            return ResponseEntity.ok(Map.of("success", true));
        } catch (RegistrationFailedException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * 認証開始: チャレンジと許可する認証器のリストをクライアントに返す
     */
    @PostMapping("/api/webauthn/authenticate/start")
    @ResponseBody
    public ResponseEntity<String> startAuthentication(@RequestBody AuthenticationStartRequest request, HttpSession session) {
        try {
            AssertionRequest assertionRequest = webAuthnService.startAuthentication(request.getUsername());

            // チャレンジを検証するため、セッションに保存
            session.setAttribute(ASSERTION_REQUEST_KEY, assertionRequest);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(assertionRequest.toJson());
        } catch (JsonProcessingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to serialize authentication options\"}");
        }
    }

    /**
     * 認証完了: クライアントから受け取った署名を検証
     */
    @PostMapping("/api/webauthn/authenticate/finish")
    @ResponseBody
    public ResponseEntity<?> finishAuthentication(@RequestBody AuthenticationFinishRequest request, HttpSession session) {
        try {
            AssertionRequest assertionRequest =
                    (AssertionRequest) session.getAttribute(ASSERTION_REQUEST_KEY);
            if (assertionRequest == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "No authentication in progress"));
            }

            String username = webAuthnService.finishAuthentication(assertionRequest, request.getCredential());
            session.removeAttribute(ASSERTION_REQUEST_KEY);

            return ResponseEntity.ok(Map.of("success", true, "username", username));
        } catch (AssertionFailedException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // ===== DTOs =====

    @Data
    public static class RegistrationStartRequest {
        private String username;
    }

    @Data
    public static class RegistrationFinishRequest {
        private String username;
        private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential;
    }

    @Data
    public static class AuthenticationStartRequest {
        private String username;
    }

    @Data
    public static class AuthenticationFinishRequest {
        private String username;
        private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential;
    }
}
