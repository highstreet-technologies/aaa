package org.opendaylight.aaa.shiro.oauth.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.BearerToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.subject.Subject;
import org.opendaylight.aaa.api.IIDMStore;
import org.opendaylight.aaa.api.IdMService;
import org.opendaylight.aaa.shiro.oauth.data.Config;
import org.opendaylight.aaa.shiro.oauth.data.InvalidConfigurationException;
import org.opendaylight.aaa.shiro.oauth.data.NoDefinitionFoundException;
import org.opendaylight.aaa.shiro.oauth.data.OAuthProviderConfig;
import org.opendaylight.aaa.shiro.oauth.data.OAuthToken;
import org.opendaylight.aaa.shiro.oauth.data.OdlPolicy;
import org.opendaylight.aaa.shiro.oauth.data.UnableToConfigureOAuthService;
import org.opendaylight.aaa.shiro.oauth.data.UserTokenPayload;
import org.opendaylight.aaa.shiro.oauth.http.client.BaseHTTPClient;
import org.opendaylight.aaa.shiro.oauth.providers.AuthService;
import org.opendaylight.aaa.shiro.oauth.providers.AuthService.PublicOAuthProviderConfig;
import org.opendaylight.aaa.shiro.oauth.providers.MdSalAuthorizationStore;
import org.opendaylight.aaa.shiro.oauth.providers.OAuthProviderFactory;
import org.opendaylight.aaa.shiro.oauth.providers.TokenCreator;
import org.opendaylight.aaa.shiro.web.env.AAAShiroWebEnvironment;
import org.opendaylight.yang.gen.v1.urn.opendaylight.aaa.app.config.rev170619.ShiroConfiguration;
import org.opendaylight.yang.gen.v1.urn.opendaylight.aaa.app.config.rev170619.shiro.ini.Main;
import org.opendaylight.yang.gen.v1.urn.opendaylight.aaa.app.config.rev170619.shiro.ini.Urls;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/oauth")
public class AuthHttpHandler {

    private final ObjectMapper mapper;
    /* state <=> AuthProviderService> */
    private static final Logger LOG = LoggerFactory.getLogger(AuthHttpHandler.class.getName());
    public static final String BASEURI = "/oauth";
    private static final String LOGINURI = BASEURI + "/login";
    private static final String LOGOUTURI = BASEURI + "/logout";
    private static final String PROVIDERSURI = BASEURI + "/providers";
    public static final String REDIRECTURI = BASEURI + "/redirect";
    private static final String REDIRECTURI_FORMAT = REDIRECTURI + "/%s";
    private static final String POLICIESURI = BASEURI + "/policies";
    public static final String LOGIN_REDIRECT_FORMAT = LOGINURI + "/%s";
    private static final String LOGOUT_REDIRECT_URL_PARAMETER = "redirect_uri";
    private static final String HEAEDER_AUTHORIZATION = "Authorization";
    private static final String DEFAULT_DOMAIN = "sdn";
    private static final String CLASSNAME_ODLBASICAUTH =
            "org.opendaylight.aaa.shiro.filters.ODLHttpAuthenticationFilter";
    private static final String CLASSNAME_ODLBEARERANDBASICAUTH =
            "org.opendaylight.aaa.shiro.filters.ODLHttpAuthenticationFilter2";
    private static final String CLASSNAME_ODLMDSALAUTH =
            "org.opendaylight.aaa.shiro.realm.MDSALDynamicAuthorizationFilter";
    private final Map<String, AuthService> providerStore;
    private final TokenCreator tokenCreator;
    private final Config config;
    private final AAAShiroWebEnvironment env;
    private final IdMService odlIdentityService;
    private final ShiroConfiguration shiroConfiguration;
    private final MdSalAuthorizationStore mdsalAuthStore;

    public AuthHttpHandler(final AAAShiroWebEnvironment env, final IdMService odlIdentityService,
                           ShiroConfiguration shiroConfiguration,  MdSalAuthorizationStore mdsalAuthStore) throws IllegalArgumentException, IOException, InvalidConfigurationException,
            UnableToConfigureOAuthService {
        this.config = Config.getInstance();
        this.tokenCreator = TokenCreator.getInstance(this.config);
        this.env = env;
        this.mapper = new ObjectMapper();
        this.providerStore = new HashMap<>();
        for (OAuthProviderConfig pc : config.getProviders()) {
            this.providerStore.put(pc.getId(), OAuthProviderFactory.create(pc.getType(), pc,
                    this.config.getRedirectUri(), TokenCreator.getInstance(this.config)));
        }
        this.odlIdentityService = odlIdentityService;
        this.shiroConfiguration = shiroConfiguration;
        this.mdsalAuthStore = mdsalAuthStore;
    }

    @GET
    @Path("/providers")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getProviders() {
        return Response.ok(getConfigs(this.providerStore.values())).build();
    }

    @GET
    @Path("/policies")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPolicies(@Context HttpHeaders headers) {
        return Response.ok(this.getPoliciesForUser(headers)).build();
    }

    @GET
    @Path("/login/{providerId}")
    public Response handleLoginRedirect(@PathParam("providerId") String providerId)
            throws IOException, URISyntaxException {
        AuthService provider = this.providerStore.getOrDefault(providerId, null);
        if (provider != null) {
            String redirectUrl = getHost(null) + String.format(REDIRECTURI_FORMAT, providerId);
            return provider.sendLoginRedirectResponse(redirectUrl);

        }
        return Response.status(Status.NOT_FOUND).build();
    }

    /**
     * GET /oauth/redirect/{providerID}
     *
     * @throws IOException
     */
    @GET
    @Path("/redirect/{providerId}")
    private Response handleRedirect(@PathParam("providerId") String providerId, @Context UriInfo uriInfo,
                                    @Context HttpHeaders headers) throws IOException, URISyntaxException {
        AuthService provider = this.providerStore.getOrDefault(providerId, null);
        if (provider != null) {
            //provider.setLocalHostUrl(getHost(req));
            return provider.handleRedirect(uriInfo, getHost(uriInfo));
        }
        return Response.status(Status.NOT_FOUND).build();
    }

    @GET
    @Path("/logout")
    public Response logout(@DefaultValue("") @QueryParam(LOGOUT_REDIRECT_URL_PARAMETER) String redirectUrl,
                           @Context HttpHeaders headers) throws IOException, URISyntaxException {
        ;
        final String bearerToken = this.tokenCreator.getBearerToken(headers, true);
        if (redirectUrl == null || redirectUrl.isBlank()) {
            redirectUrl = this.config.getPublicUrl();
        }
        // if nothing configured and nothing from request
        if (redirectUrl == null || redirectUrl.isBlank()) {
            redirectUrl = "/";
        }

        UserTokenPayload userInfo = this.tokenCreator.decode(bearerToken);
        if (bearerToken != null && userInfo != null && !userInfo.isInternal()) {
            AuthService provider = this.providerStore.getOrDefault(userInfo.getProviderId(), null);

            if (provider != null) {
                Response resp = provider.sendLogoutRedirectResponse(bearerToken, redirectUrl);
                this.logout();
                return resp;
            }
        }
        this.logout();
        return Response.temporaryRedirect(new URI(redirectUrl)).build();

    }

    /**
     * find out what urls can be accessed by user and which are forbidden
     * <p>
     * urlEntries: "anon" -> any access allowed "authcXXX" -> no grouping rule -> any access for user allowed "authcXXX,
     * roles[abc] -> user needs to have role abc "authcXXX, roles["abc,def"] -> user needs to have roles abc AND def
     * "authcXXX, anyroles[abc] -> user needs to have role abc "authcXXX, anyroles["abc,def"] -> user needs to have
     * roles abc OR def
     *
     * @return
     */
    private List<OdlPolicy> getPoliciesForUser(HttpHeaders headers) {
        List<Urls> urlRules = shiroConfiguration.getUrls();
        UserTokenPayload data = this.getUserInfo(headers);
        List<OdlPolicy> policies = new ArrayList<>();
        if (urlRules != null) {
            LOG.debug("try to find rules for user {} with roles {}",
                    data == null ? "null" : data.getPreferredUsername(), data == null ? "null" : data.getRoles());
            final String regex = "^([^,]+)[,]?[\\ ]?([anyroles]+)?(\\[\"?([a-zA-Z,]+)\"?\\])?";
            final Pattern pattern = Pattern.compile(regex);
            Matcher matcher;
            for (Urls urlRule : urlRules) {
                matcher = pattern.matcher(urlRule.getPairValue());
                if (matcher.find()) {
                    try {
                        final String authClass = getAuthClass(matcher.group(1));
                        Optional<OdlPolicy> policy = Optional.empty();
                        //anon access allowed
                        if (authClass == null) {
                            policy = Optional.of(OdlPolicy.allowAll(urlRule.getPairKey()));
                        } else if (authClass.equals(CLASSNAME_ODLBASICAUTH)) {
                            policy = isBasic(headers) ? this.getTokenBasedPolicy(urlRule, matcher, data)
                                    : Optional.of(OdlPolicy.denyAll(urlRule.getPairKey()));
                        } else if (authClass.equals(CLASSNAME_ODLBEARERANDBASICAUTH)) {
                            policy = this.getTokenBasedPolicy(urlRule, matcher, data);
                        } else if (authClass.equals(CLASSNAME_ODLMDSALAUTH)) {
                            policy = this.getMdSalBasedPolicy(urlRule, data);
                        }
                        if (policy.isPresent()) {
                            policies.add(policy.get());
                        } else {
                            LOG.warn("unable to get policy for authClass {} for entry {}", authClass,
                                    urlRule.getPairValue());
                            policies.add(OdlPolicy.denyAll(urlRule.getPairKey()));
                        }
                    } catch (NoDefinitionFoundException e) {
                        LOG.warn("unknown authClass: ", e);
                    }

                } else {
                    LOG.warn("unable to detect url role value: {}", urlRule.getPairValue());
                }
            }
        } else {
            LOG.debug("no url rules found");
        }
        return policies;
    }

    /**
     * extract policy rule for user from MD-SAL not yet supported
     *
     * @param urlRule
     * @param data
     * @return
     */
    private Optional<OdlPolicy> getMdSalBasedPolicy(Urls urlRule, UserTokenPayload data) {
        if (mdsalAuthStore != null) {
            return data != null ? mdsalAuthStore.getPolicy(urlRule.getPairKey(), data.getRoles())
                    : Optional.of(OdlPolicy.denyAll(urlRule.getPairKey()));
        }
        return Optional.empty();
    }

    /**
     * extract policy rule for user from url rules of config
     *
     * @param urlRule
     * @param matcher
     * @param data
     * @return
     */
    private Optional<OdlPolicy> getTokenBasedPolicy(Urls urlRule, Matcher matcher, UserTokenPayload data) {
        final String url = urlRule.getPairKey();
        final String rule = urlRule.getPairValue();
        if (!rule.contains(",")) {
            LOG.debug("found rule without roles for '{}'", matcher.group(1));
            //not important if anon or authcXXX
            if (data != null || "anon".equals(matcher.group(1))) {
                return Optional.of(OdlPolicy.allowAll(url));
            }
        }
        if (data != null) {
            LOG.debug("found rule with roles '{}'", matcher.group(4));
            if ("roles".equals(matcher.group(2))) {
                if (this.rolesMatch(data.getRoles(), Arrays.asList(matcher.group(4).split(",")), false)) {
                    return Optional.of(OdlPolicy.allowAll(url));
                } else {
                    return Optional.of(OdlPolicy.denyAll(url));
                }
            } else if ("anyroles".equals(matcher.group(2))) {
                if (this.rolesMatch(data.getRoles(), Arrays.asList(matcher.group(4).split(",")), true)) {
                    return Optional.of(OdlPolicy.allowAll(url));
                } else {
                    return Optional.of(OdlPolicy.denyAll(url));
                }
            } else {
                LOG.warn("unable to detect url role value: {}", urlRule.getPairValue());
            }
        } else {
            return Optional.of(OdlPolicy.denyAll(url));
        }
        return Optional.empty();
    }

    private boolean rolesMatch(List<String> userRoles, List<String> policyRoles, boolean any) {
        if (any) {
            for (String policyRole : policyRoles) {
                if (userRoles.contains(policyRole)) {
                    return true;
                }
            }
            return false;
        } else {
            for (String policyRole : policyRoles) {
                if (!userRoles.contains(policyRole)) {
                    return false;
                }
            }
            return true;
        }

    }

    private String getAuthClass(String key) throws NoDefinitionFoundException {
        if ("anon".equals(key)) {
            return null;
        }
        List<Main> list = shiroConfiguration.getMain();
        Optional<Main> main =
                list == null ? Optional.empty() : list.stream().filter(e -> e.getPairKey().equals(key)).findFirst();
        if (main.isPresent()) {
            return main.get().getPairValue();
        }
        throw new NoDefinitionFoundException("unable to find def for " + key);
    }

    private UserTokenPayload getUserInfo(HttpHeaders headers) {
        if (isBearer(headers)) {
            UserTokenPayload data = this.tokenCreator.decode(headers);
            if (data != null) {
                return data;
            }
        } else if (isBasic(headers)) {
            String username = getBasicAuthUsername(headers);
            if (username != null) {
                final String domain = getBasicAuthDomain(username);
                if (!username.contains("@")) {
                    username = String.format("%s@%s", username, domain);
                }
                List<String> roles = odlIdentityService.listRoles(username, domain);
                return UserTokenPayload.createInternal(username, roles);
            }
        }
        return null;
    }

    private static String getBasicAuthUsername(HttpHeaders headers) {
        final List<String> header = headers.getRequestHeader(HEAEDER_AUTHORIZATION);
        if (header != null && header.size() > 0) {
            final String decoded = Base64.decodeToString(header.get(0).substring(6));
            // attempt to decode username/password; otherwise decode as token
            if (decoded.contains(":")) {
                return decoded.split(":")[0];
            }
        }
        LOG.warn("unable to detect username from basicauth header {}", header);
        return null;
    }

    private static String getBasicAuthDomain(String username) {
        if (username.contains("@")) {
            return username.split("@")[1];
        }
        return DEFAULT_DOMAIN;
    }

    private static boolean isBasic(HttpHeaders headers) {
        final List<String> header = headers.getRequestHeader(HEAEDER_AUTHORIZATION);
        return header == null || header.size() <= 0 ? false : header.get(0).startsWith("Basic");
    }

    private static boolean isBearer(HttpHeaders headers) {
        final List<String> header = headers.getRequestHeader(HEAEDER_AUTHORIZATION);
        return header == null || header.size() <= 0 ? false : header.get(0).startsWith("Bearer");
    }

    private void logout() {
        final Subject subject = SecurityUtils.getSubject();
        try {
            subject.logout();
            Session session = subject.getSession(false);
            if (session != null) {
                session.stop();
            }
        } catch (ShiroException e) {
            LOG.debug("Couldn't log out {}", subject, e);
        }
    }

    public String getHost(@Context UriInfo uriInfo) {
        String hostUrl = this.config.getPublicUrl();
        if (hostUrl == null) {
            hostUrl = uriInfo.getBaseUri().getHost();

        }
        LOG.debug("host={}", hostUrl);
        return hostUrl;

    }

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(@FormParam("username") final String username, @FormParam("password") final String password,
                          @FormParam("domain") final String domain) {
        LOG.debug("POST request for {}", LOGINURI);
        if (this.config.loginActive() && this.config.doSupportOdlUsers()) {
            BearerToken token = this.doLogin(username, password, domain != null ? domain : DEFAULT_DOMAIN);
            if (token != null) {
                LOG.debug("login for odluser {} succeeded", username);
                return Response.ok(new OAuthToken(token)).build();
            } else {
                LOG.debug("login failed");
            }

        }
        return Response.status(Status.NOT_FOUND).build();
    }

    private BearerToken doLogin(String username, String password, String domain) {
        if (!username.contains("@")) {
            username = String.format("%s@%s", username, domain);
        }
        HttpServletRequest req = new HeadersOnlyHttpServletRequest(
                Map.of("Authorization", BaseHTTPClient.getAuthorizationHeaderValue(username, password)));
        if (authenticate(req)) {
            List<String> roles = odlIdentityService.listRoles(username, domain);
            UserTokenPayload data = new UserTokenPayload();
            data.setPreferredUsername(username);
            data.setFamilyName("");
            data.setGivenName(username);
            data.setIat(this.tokenCreator.getDefaultIat());
            data.setExp(this.tokenCreator.getDefaultExp());
            data.setRoles(roles);
            return this.tokenCreator.createNewJWT(data);

        }
        return null;
    }

    private boolean authenticate(HttpServletRequest httpServletRequest) {
        final String authorization = httpServletRequest.getHeader("Authorization");

        LOG.trace("Incoming Jolokia authentication attempt: {}", authorization);

        if (authorization == null || !authorization.startsWith("Basic")) {
            return false;
        }

        try {
            final String base64Creds = authorization.substring("Basic".length()).trim();
            final String credentials = new String(java.util.Base64.getDecoder().decode(base64Creds), StandardCharsets.UTF_8);
            final String[] values = credentials.split(":", 2);
            final UsernamePasswordToken upt = new UsernamePasswordToken();
            upt.setUsername(values[0]);
            upt.setPassword(values[1].toCharArray());

            final Subject subject = new Subject.Builder(env.getSecurityManager()).buildSubject();
            try {
                return login(subject, upt);
            } catch (UnknownSessionException e) {
                LOG.debug("Couldn't log in {} - logging out and retrying...", upt, e);
                logout(subject);
                return login(subject, upt);
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            // FIXME: who throws this above and why do we need to catch it? Should this be error or warn?
            LOG.trace("Formatting issue with basic auth credentials: {}", authorization, e);
        }

        return false;
    }

    private List<PublicOAuthProviderConfig> getConfigs(Collection<AuthService> values) {
        List<PublicOAuthProviderConfig> configs = new ArrayList<>();
        for (AuthService svc : values) {
            configs.add(svc.getConfig());
        }
        return configs;
    }

    private static void logout(final Subject subject) {
        try {
            subject.logout();
            Session session = subject.getSession(false);
            if (session != null) {
                session.stop();
            }
        } catch (ShiroException e) {
            LOG.debug("Couldn't log out {}", subject, e);
        }
    }

    private static boolean login(final Subject subject, final UsernamePasswordToken upt) {
        try {
            subject.login(upt);
        } catch (AuthenticationException e) {
            LOG.trace("Couldn't authenticate the subject: {}", subject, e);
            return false;
        }
        return true;
    }
}
