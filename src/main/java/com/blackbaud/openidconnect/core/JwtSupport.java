package com.blackbaud.openidconnect.core;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.ServerErrorException;
import javax.ws.rs.core.Response;
import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.sql.Date;
import java.text.ParseException;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

@Slf4j
@Component
public class JwtSupport {
    private static final int LIFETIME_IN_MINUTES = 20;
    private static final String RESOURCE_CLAIM = "rsc";
    private static final String NONCE_CLAIM = "nonce";
    private static final String ISSUER_URI = "https://ui.blackbaudcloud.com";

    @Inject
    private Clock clock;

    private byte[] sharedSecret = new byte[32];

    JwtSupport() {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(sharedSecret);
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class Context {
        private String resource;
        private UUID nonce;
    }

    public String createStateToken(Context ctx) {
        JWSSigner signer;
        try {
            signer = new MACSigner(sharedSecret);
        } catch (KeyLengthException e) {
            throw new ServerErrorException("unable to create JWSSigner", Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        LocalDateTime now = LocalDateTime.now(clock);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("Bob Dobbs")
                .issuer(ISSUER_URI)
                .issueTime(Date.from(now.toInstant(ZoneOffset.UTC)))
                .expirationTime(Date.from(now.plusMinutes(LIFETIME_IN_MINUTES).toInstant(ZoneOffset.UTC)))
                .claim(RESOURCE_CLAIM, ctx.getResource())
                .claim(NONCE_CLAIM, ctx.getNonce().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSet);

        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new ServerErrorException("unable to sign jwt", Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        return signedJWT.serialize();
    }

    public Context validateStateToken(String jwt) {
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(jwt);
        } catch (ParseException e) {
            throw new ServerErrorException("unable to parse jwt", Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        MACVerifier verifier;
        try {
            verifier = new MACVerifier(sharedSecret);
        } catch (JOSEException e) {
            throw new ServerErrorException("unable to create verifier", Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        try {
            if (!signedJWT.verify(verifier)) {
                throw new BadRequestException("invalid signature");
            }

            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            return Context.builder()
                    .resource(jwtClaimsSet.getStringClaim(RESOURCE_CLAIM))
                    .nonce(UUID.fromString(jwtClaimsSet.getStringClaim(NONCE_CLAIM)))
                    .build();
        } catch (ParseException | JOSEException e) {
            throw new ServerErrorException("unable to validate jwt", Response.Status.INTERNAL_SERVER_ERROR, e);
        }
    }

    public void validateIdToken(String idToken, OpenidConnectConfigurationFactory.Config config, Context context) {
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(idToken);
        } catch (ParseException e) {
            throw new ServerErrorException("unable to parse id_token", Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        String x5t = signedJWT.getHeader().getX509CertThumbprint().toString();

        Key key = config.getKeys().get(x5t);

        RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) key);

        try {
            if (!signedJWT.verify(verifier)) {
                throw new BadRequestException("invalid id_token");
            }
        } catch (JOSEException e) {
            throw new ServerErrorException("unable to verify id_token", Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        try {
            if (context.getNonce().compareTo(UUID.fromString(signedJWT.getJWTClaimsSet().getStringClaim("nonce"))) != 0) {
                throw new BadRequestException("invalid id_token");
            }
        } catch (ParseException e) {
            throw new ServerErrorException("unable to extract nonce", Response.Status.INTERNAL_SERVER_ERROR, e);
        }
    }
}
