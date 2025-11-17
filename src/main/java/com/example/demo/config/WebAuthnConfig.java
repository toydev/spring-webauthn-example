package com.example.demo.config;

import com.example.demo.service.RegistrationService;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

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
