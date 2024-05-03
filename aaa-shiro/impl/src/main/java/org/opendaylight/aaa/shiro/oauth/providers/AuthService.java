/*
 * ============LICENSE_START=======================================================
 * ONAP : ccsdk features
 * ================================================================================
 * Copyright (C) 2020 highstreet technologies GmbH Intellectual Property.
 * All rights reserved.
 * ================================================================================
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ============LICENSE_END=========================================================
 *
 */
package org.opendaylight.aaa.shiro.oauth.providers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;
import org.apache.shiro.authc.BearerToken;
import org.opendaylight.aaa.shiro.oauth.data.OAuthProviderConfig;
import org.opendaylight.aaa.shiro.oauth.data.OAuthResponseData;
import org.opendaylight.aaa.shiro.oauth.data.OpenIdConfigResponseData;
import org.opendaylight.aaa.shiro.oauth.data.UnableToConfigureOAuthService;
import org.opendaylight.aaa.shiro.oauth.data.UserTokenPayload;
import org.opendaylight.aaa.shiro.oauth.http.AuthHttpHandler;
import org.opendaylight.aaa.shiro.oauth.http.client.MappedBaseHttpResponse;
import org.opendaylight.aaa.shiro.oauth.http.client.MappingBaseHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AuthService {


    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);
    private final MappingBaseHttpClient httpClient;
    protected final ObjectMapper mapper;
    protected final OAuthProviderConfig config;
    protected final TokenCreator tokenCreator;
    private final String redirectUri;
    private final String tokenEndpointRelative;
    private final String authEndpointAbsolute;
    private final String logoutEndpointAbsolute;

    private final Map<String, String> logoutTokenMap;

    protected abstract String getTokenVerifierUri();

    protected abstract Map<String, String> getAdditionalTokenVerifierParams();

    protected abstract ResponseType getResponseType();

    protected abstract boolean doSeperateRolesRequest();

    protected abstract UserTokenPayload mapAccessToken(String spayload)
            throws JsonProcessingException;

    protected abstract String getLoginUrl(String callbackUrl);

    protected abstract String getLogoutUrl();

    protected abstract UserTokenPayload requestUserRoles(String access_token, long issued_at, long expires_at);

    protected abstract boolean verifyState(String state);

    public AuthService(OAuthProviderConfig config, String redirectUri, TokenCreator tokenCreator)
            throws UnableToConfigureOAuthService {
        this.config = config;
        this.tokenCreator = tokenCreator;
        this.redirectUri = redirectUri;
        this.mapper = new ObjectMapper();
        this.mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.httpClient = new MappingBaseHttpClient(this.config.getUrlOrInternal(), this.config.trustAll());
        this.logoutTokenMap = new HashMap<>();
        if (this.config.hasToBeConfigured()) {
            Optional<MappedBaseHttpResponse<OpenIdConfigResponseData>> oresponse = this.httpClient.sendMappedRequest(
                    this.config.getOpenIdConfigUrl(), "GET", null, null, OpenIdConfigResponseData.class);
            if (oresponse.isEmpty()) {
                throw new UnableToConfigureOAuthService(this.config.getOpenIdConfigUrl());
            }
            MappedBaseHttpResponse<OpenIdConfigResponseData> response = oresponse.get();
            if (!response.isSuccess()) {
                throw new UnableToConfigureOAuthService(this.config.getOpenIdConfigUrl(), response.code);
            }
            this.tokenEndpointRelative = trimUrl(this.config.getUrlOrInternal(), response.body.getToken_endpoint());
            this.authEndpointAbsolute =
                    extendUrl(this.config.getUrlOrInternal(), response.body.getAuthorization_endpoint());
            this.logoutEndpointAbsolute =
                    extendUrl(this.config.getUrlOrInternal(), response.body.getEnd_session_endpoint());
        } else {
            this.tokenEndpointRelative = null;
            this.authEndpointAbsolute = null;
            this.logoutEndpointAbsolute = null;
        }
    }

    public static String trimUrl(String baseUrl, String endpoint) {
        if (endpoint.startsWith(baseUrl)) {
            return endpoint.substring(baseUrl.length());
        }
        if (endpoint.startsWith("http")) {
            return endpoint.substring(endpoint.indexOf("/", 8));
        }
        return endpoint;
    }

    public static String extendUrl(String baseUrl, String endpoint) {
        if (endpoint.startsWith("http")) {
            endpoint = endpoint.substring(endpoint.indexOf("/", 8));
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 2);
        }
        return baseUrl + endpoint;
    }

    public PublicOAuthProviderConfig getConfig() {
        return new PublicOAuthProviderConfig(this);
    }

    protected MappingBaseHttpClient getHttpClient() {
        return this.httpClient;
    }

    public Response handleRedirect(UriInfo uriInfo, String host)
            throws IOException, URISyntaxException {
        switch (this.getResponseType()) {
            case CODE:
                return this.handleRedirectCode(uriInfo, host);
            case TOKEN:
                return sendErrorResponse("not yet implemented");
            case SESSION_STATE:
                break;
        }
        return Response.status(Status.NOT_FOUND).build();
    }

    public Response sendLoginRedirectResponse(String callbackUrl) throws URISyntaxException {
        String url = this.authEndpointAbsolute != null ? String.format(
                "%s?client_id=%s&response_type=code&scope=%s&redirect_uri=%s",
                this.authEndpointAbsolute, urlEncode(this.config.getClientId()), this.config.getScope(),
                urlEncode(callbackUrl)) : this.getLoginUrl(callbackUrl);

        return Response.temporaryRedirect(new URI(url)).build();
    }

    public Response sendLogoutRedirectResponse(String token, String redirectUrl) throws URISyntaxException {
        String idToken = this.logoutTokenMap.getOrDefault(token, null);
        String logoutEndpoint = this.logoutEndpointAbsolute != null ? this.logoutEndpointAbsolute : this.getLogoutUrl();
        if (idToken == null) {
            LOG.debug("unable to find token in map. Do unsafe logout.");
            return Response.temporaryRedirect(new URI(this.logoutEndpointAbsolute)).build();
        }
        LOG.debug("id token found. redirect to specific logout");
        return Response.temporaryRedirect(
                new URI(String.format("%s?id_token_hint=%s&post_logout_redirect_uri=%s", logoutEndpoint, idToken,
                        urlEncode(redirectUrl)))).build();
    }

    private static Response sendErrorResponse(String message) {
        return Response.status(Status.NOT_FOUND).entity(message).build();
    }

    private Response handleRedirectCode(UriInfo uriInfo, String host)
            throws IOException, URISyntaxException {
        final List<String> code = uriInfo.getQueryParameters().get("code");
        final List<String> state = uriInfo.getQueryParameters().get("state");
        OAuthResponseData response = null;
        if (code == null || code.size() <= 0 || state == null || state.size() <= 0) {
            return sendErrorResponse("unable to get code or state");
        }
        if (this.verifyState(state.get(0))) {
            response = this.getTokenForUser(code.get(0), host);
        }
        if (response != null) {
            if (this.doSeperateRolesRequest()) {
                LOG.debug("do a seperate role request");
                long expiresAt = this.tokenCreator.getDefaultExp();
                long issuedAt = this.tokenCreator.getDefaultIat();
                UserTokenPayload data = this.requestUserRoles(response.getAccess_token(), issuedAt, expiresAt);
                if (data != null) {
                    BearerToken createdToken = this.handleUserInfoToken(data);
                    this.logoutTokenMap.put(createdToken.getToken(), response.getId_token());
                } else {
                    return sendErrorResponse("unable to verify user");
                }
            } else {
                BearerToken createdToken = this.handleUserInfoToken(response.getAccess_token(), host);
                if (createdToken != null) {
                    this.logoutTokenMap.put(createdToken.getToken(), response.getId_token());
                    return sendTokenResponse(createdToken, host);
                }
            }
        }
        return sendErrorResponse("unable to verify code");

    }

    private BearerToken handleUserInfoToken(UserTokenPayload data) {
        return this.tokenCreator.createNewJWT(data);
    }

    private BearerToken handleUserInfoToken(String accessToken, String localHostUrl) {
        try {
            DecodedJWT jwt = JWT.decode(accessToken);
            String spayload = base64Decode(jwt.getPayload());
            LOG.debug("payload in jwt='{}'", spayload);
            UserTokenPayload data = this.mapAccessToken(spayload);
            return this.handleUserInfoToken(data);
        } catch (JWTDecodeException | JsonProcessingException e) {
            LOG.warn("unable to decode jwt token {}: ", accessToken, e);
        }
        return null;
    }


    protected List<String> mapRoles(List<String> roles) {
        final Map<String, String> map = this.config.getRoleMapping();
        return roles.stream().map(r -> map.getOrDefault(r, r)).collect(Collectors.toList());
    }

    private Response sendTokenResponse(BearerToken data, String localHostUrl) throws URISyntaxException {
        if (this.redirectUri == null) {
            return Response.ok(this.tokenCreator.createAuthCookie(data)).build();
        } else {
            return Response.temporaryRedirect(new URI(assembleUrl(localHostUrl, this.redirectUri, data.getToken())))
                    .cookie(this.tokenCreator.createAuthCookie(data)).build();
        }
    }


    private static String base64Decode(String data) {
        return new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8);
    }

    private OAuthResponseData getTokenForUser(String code, String localHostUrl) {

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("Accept", "application/json");
        Map<String, String> params = this.getAdditionalTokenVerifierParams();
        params.put("code", code);
        params.put("client_id", this.config.getClientId());
        params.put("client_secret", this.config.getSecret());
        params.put("redirect_uri", assembleRedirectUrl(localHostUrl, AuthHttpHandler.REDIRECTURI, this.config.getId()));
        StringBuilder body = new StringBuilder();
        for (Entry<String, String> p : params.entrySet()) {
            body.append(String.format("%s=%s&", p.getKey(), urlEncode(p.getValue())));
        }

        String url = this.tokenEndpointRelative != null ? this.tokenEndpointRelative : this.getTokenVerifierUri();
        Optional<MappedBaseHttpResponse<OAuthResponseData>> response =
                this.httpClient.sendMappedRequest(url, "POST",
                        body.substring(0, body.length() - 1), headers, OAuthResponseData.class);
        if (response.isPresent() && response.get().isSuccess()) {
            return response.get().body;
        }
        LOG.warn("problem get token for code {}", code);

        return null;
    }

    /**
     * Assemble callback url for service provider {host}{baseUri}/{serviceId} e.g.
     * http://10.20.0.11:8181/oauth/redirect/keycloak
     *
     * @param host
     * @param baseUri
     * @param serviceId
     * @return
     */
    public static String assembleRedirectUrl(String host, String baseUri, String serviceId) {
        return String.format("%s%s/%s", host, baseUri, serviceId);
    }

    private static String assembleUrl(String host, String uri, String token) {
        return String.format("%s%s%s", host, uri, token);
    }

    public static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }


    public enum ResponseType {
        CODE, TOKEN, SESSION_STATE
    }


    public static class PublicOAuthProviderConfig {

        private String id;
        private String title;
        private String loginUrl;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getTitle() {
            return title;
        }

        public void setTitle(String title) {
            this.title = title;
        }

        public String getLoginUrl() {
            return loginUrl;
        }

        public void setLoginUrl(String loginUrl) {
            this.loginUrl = loginUrl;
        }

        public PublicOAuthProviderConfig(AuthService authService) {
            this.id = authService.config.getId();
            this.title = authService.config.getTitle();
            this.loginUrl = String.format(AuthHttpHandler.LOGIN_REDIRECT_FORMAT, authService.config.getId());
        }

    }


}
