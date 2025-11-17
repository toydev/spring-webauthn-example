package com.example.demo.config;

import com.example.demo.service.RegistrationService;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;

@Configuration
@RequiredArgsConstructor
public class WebAuthnConfig {

    private final RegistrationService registrationService;

    @Bean
    public RelyingParty relyingParty() {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id("localhost")
                .name("WebAuthn Demo")
                .build();

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(registrationService)
                .origins(java.util.Set.of("http://localhost:8080"))
                .build();
    }

    @Bean
    public SecureRandom secureRandom() {
        return new SecureRandom();
    }
}
