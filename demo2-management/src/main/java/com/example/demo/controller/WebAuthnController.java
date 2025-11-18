package com.example.demo.controller;

import com.example.demo.backend.AuthenticatorInfo;
import com.example.demo.backend.UserInfo;
import com.example.demo.backend.WebAuthnBackend;
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
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class WebAuthnController {

    private final WebAuthnService webAuthnService;
    private final WebAuthnBackend backend;

    private static final String REGISTRATION_REQUEST_KEY = "webauthn.registration.request";
    private static final String ASSERTION_REQUEST_KEY = "webauthn.assertion.request";
    private static final String SESSION_USERNAME_KEY = "username";

    // ===== 画面表示 =====

    @GetMapping("/")
    public String index(HttpSession session, Model model) {
        String username = (String) session.getAttribute(SESSION_USERNAME_KEY);

        if (username != null) {
            // 認証済み: 認証器一覧を取得
            List<AuthenticatorDto> authenticators = backend.findUserByUsername(username)
                    .map(UserInfo::getAuthenticators)
                    .orElse(List.of())
                    .stream()
                    .map(auth -> new AuthenticatorDto(
                            Base64.getUrlEncoder().withoutPadding().encodeToString(auth.getCredentialId()),
                            auth.getNickname()
                    ))
                    .collect(Collectors.toList());

            model.addAttribute("username", username);
            model.addAttribute("authenticators", authenticators);
        }

        return "index";
    }

    @PostMapping("/authenticator/delete")
    public String deleteAuthenticator(
            @RequestParam String credentialId,
            HttpSession session,
            RedirectAttributes redirectAttributes) {

        String username = (String) session.getAttribute(SESSION_USERNAME_KEY);
        if (username == null) {
            redirectAttributes.addFlashAttribute("error", "ログインが必要です");
            return "redirect:/";
        }

        try {
            byte[] credIdBytes = Base64.getUrlDecoder().decode(credentialId);
            boolean deleted = backend.deleteAuthenticator(username, credIdBytes);

            if (deleted) {
                redirectAttributes.addFlashAttribute("message", "認証器を削除しました");
            } else {
                redirectAttributes.addFlashAttribute("error", "認証器の削除に失敗しました");
            }
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("error", "無効なcredentialIdです");
        }

        return "redirect:/";
    }

    @PostMapping("/logout")
    public String logout(HttpSession session, RedirectAttributes redirectAttributes) {
        session.invalidate();
        redirectAttributes.addFlashAttribute("message", "ログアウトしました");
        return "redirect:/";
    }

    // ===== WebAuthn API =====

    @PostMapping("/api/webauthn/register/start")
    @ResponseBody
    public ResponseEntity<String> startRegistration(@RequestBody RegistrationStartRequest request, HttpSession session) {
        try {
            PublicKeyCredentialCreationOptions options =
                    webAuthnService.startRegistration(request.getUsername());
            session.setAttribute(REGISTRATION_REQUEST_KEY, options);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(options.toJson());
        } catch (JsonProcessingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to serialize registration options\"}");
        }
    }

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
                    request.getCredential(),
                    request.getNickname()
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

    @PostMapping("/api/webauthn/authenticate/start")
    @ResponseBody
    public ResponseEntity<String> startAuthentication(@RequestBody AuthenticationStartRequest request, HttpSession session) {
        try {
            AssertionRequest assertionRequest = webAuthnService.startAuthentication(request.getUsername());
            session.setAttribute(ASSERTION_REQUEST_KEY, assertionRequest);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(assertionRequest.toJson());
        } catch (JsonProcessingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to serialize authentication options\"}");
        }
    }

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

            // 認証成功: セッション確立
            session.setAttribute(SESSION_USERNAME_KEY, username);

            return ResponseEntity.ok(Map.of("success", true));
        } catch (AssertionFailedException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // ===== DTOs =====

    /**
     * 画面表示用の認証器DTO。
     */
    @Data
    public static class AuthenticatorDto {
        private final String credentialIdBase64;
        private final String nickname;  // 認証器の表示名
    }

    @Data
    public static class RegistrationStartRequest {
        private String username;
    }

    @Data
    public static class RegistrationFinishRequest {
        private String username;
        private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential;
        private String nickname;  // 認証器の表示名（アプリケーション層の機能）
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
