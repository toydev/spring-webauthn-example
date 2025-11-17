package com.example.demo.controller;

import com.example.demo.service.WebAuthnService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/webauthn")
@RequiredArgsConstructor
public class WebAuthnController {

    private final WebAuthnService webAuthnService;
    private final Map<String, PublicKeyCredentialCreationOptions> registrationRequests = new ConcurrentHashMap<>();
    private final Map<String, AssertionRequest> assertionRequests = new ConcurrentHashMap<>();

    @PostMapping("/register/start")
    public ResponseEntity<?> startRegistration(@RequestBody RegistrationStartRequest request) {
        try {
            PublicKeyCredentialCreationOptions options =
                    webAuthnService.startRegistration(request.getUsername(), request.getDisplayName());
            registrationRequests.put(request.getUsername(), options);

            // デバッグ用ログ
            System.out.println("Registration options: " + options);

            return ResponseEntity.ok(options);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/register/finish")
    public ResponseEntity<?> finishRegistration(@RequestBody RegistrationFinishRequest request) {
        try {
            PublicKeyCredentialCreationOptions options = registrationRequests.get(request.getUsername());
            if (options == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "No registration in progress"));
            }

            webAuthnService.finishRegistration(
                    request.getUsername(),
                    request.getDisplayName(),
                    options,
                    request.getCredential()
            );

            registrationRequests.remove(request.getUsername());
            return ResponseEntity.ok(Map.of("success", true));
        } catch (RegistrationFailedException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/authenticate/start")
    public ResponseEntity<?> startAuthentication(@RequestBody AuthenticationStartRequest request) {
        try {
            AssertionRequest assertionRequest = webAuthnService.startAuthentication(request.getUsername());
            assertionRequests.put(request.getUsername(), assertionRequest);
            return ResponseEntity.ok(assertionRequest);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/authenticate/finish")
    public ResponseEntity<?> finishAuthentication(@RequestBody AuthenticationFinishRequest request) {
        try {
            AssertionRequest assertionRequest = assertionRequests.get(request.getUsername());
            if (assertionRequest == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "No authentication in progress"));
            }

            webAuthnService.finishAuthentication(assertionRequest, request.getCredential());
            assertionRequests.remove(request.getUsername());
            return ResponseEntity.ok(Map.of("success", true));
        } catch (AssertionFailedException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @Data
    public static class RegistrationStartRequest {
        private String username;
        private String displayName;
    }

    @Data
    public static class RegistrationFinishRequest {
        private String username;
        private String displayName;
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
