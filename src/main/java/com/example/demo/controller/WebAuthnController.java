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
import org.springframework.http.MediaType;
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
    public ResponseEntity<String> startRegistration(@RequestBody RegistrationStartRequest request) {
        try {
            PublicKeyCredentialCreationOptions options =
                    webAuthnService.startRegistration(request.getUsername());
            registrationRequests.put(request.getUsername(), options);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(options.toJson());
        } catch (JsonProcessingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to serialize registration options\"}");
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
    public ResponseEntity<String> startAuthentication(@RequestBody AuthenticationStartRequest request) {
        try {
            AssertionRequest assertionRequest = webAuthnService.startAuthentication(request.getUsername());
            assertionRequests.put(request.getUsername(), assertionRequest);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(assertionRequest.toJson());
        } catch (JsonProcessingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to serialize authentication options\"}");
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
