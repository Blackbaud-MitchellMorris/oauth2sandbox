package com.blackbaud.openidconnect.core;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.ws.rs.ServerErrorException;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.security.Key;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class OpenidConnectConfigurationFactory {

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    @JsonIgnoreProperties
    public static class Config {
        @JsonProperty("issuer")
        private String issuer;

        @JsonProperty("authorization_endpoint")
        private URI authorizationEndpoint;

        @JsonProperty("end_session_endpoint")
        private URI endSessionEndpoint;

        @JsonProperty("token_endpoint")
        private URI tokenEndpoint;

        @JsonProperty("userinfo_endpoint")
        private URI userinfoEndpoint;

        @JsonProperty("jwks_uri")
        private URI jwksUri;

        @JsonProperty("subject_types_supported")
        private List<String> subjectTypesSupported;

        @JsonProperty("scopes_supported")
        private List<String> scopesSupported;

        @JsonProperty("response_types_supported")
        private List<String> responseTypesSupported;

        @JsonProperty("response_modes_supported")
        private List<String> responseModesSupported;

        @JsonProperty("grant_types_supported")
        private List<String> grantTypesSupported;

        @JsonProperty("id_token_signing_alg_values_supported")
        private List<String> idTokenSigningAlgValuesSupported;

        @JsonProperty("claims_supported")
        private List<String> claimsSupported;

        /**
         * Mapping of keys retrieved from the jwks_uri endpoint
         */
        private Map<String, Key> keys = new HashMap<>();
    }

    /**
     * Fetch the OpenID Connect IdP configuration information from the well-known configuration endpoint
     *
     * @param baseUri the base URI for the service
     * @return a Config bean
     */
    public static Config getConfig(String baseUri) {
        log.debug(String.format("getConfig(%s) called", baseUri));

        String url = baseUri;
        if (!url.contains(".well-known")) {
            url += "/.well-known/openid-configuration";
        }

        log.debug(String.format("using url = %s", url));

        HttpGet httpGet = new HttpGet(url);

        ObjectMapper objectMapper = new ObjectMapper();

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            try (CloseableHttpResponse httpResponse = client.execute(httpGet)) {
                Config config = objectMapper.readValue(httpResponse.getEntity().getContent(), Config.class);

                updateKeys(client, config);

                return config;
            }
        } catch (IOException e) {
            throw new ServerErrorException("unable to retrieve OpenID Connect configuration", Response.Status.INTERNAL_SERVER_ERROR, e);
        }
    }

    private static void updateKeys(CloseableHttpClient client, Config config) {
        log.info(String.format("jwks_uri=%s", config.getJwksUri().toString()));

        JWKSet jwkSet;
        try {
            jwkSet = JWKSet.load(config.getJwksUri().toURL());
        } catch (IOException | ParseException e) {
            throw new ServerErrorException("unable to load jwk set", Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        for (JWK jwk : jwkSet.getKeys()) {
            log.info(String.format("jwk.class=%s, keyType=%s", jwk.getClass().getCanonicalName(), jwk.getKeyType().toString()));

            if (jwk.getKeyType().equals(KeyType.RSA)) {
                RSAKey rsaKey = (RSAKey) jwk;
                try {
                    config.getKeys().put(jwk.getKeyID(),  rsaKey.toPublicKey());
                } catch (JOSEException e) {
                    throw new ServerErrorException("unable to retrieve public key", Response.Status.INTERNAL_SERVER_ERROR, e);
                }
            }
        }
    }
}
