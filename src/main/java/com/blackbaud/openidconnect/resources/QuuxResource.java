package com.blackbaud.openidconnect.resources;

import com.blackbaud.openidconnect.api.ResourcePaths;
import com.blackbaud.openidconnect.core.JwtSupport;
import com.blackbaud.openidconnect.core.OpenidConnectConfigurationFactory;
import com.blackbaud.openidconnect.core.ResourceBean;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.concurrent.ConcurrentException;
import org.apache.commons.lang3.concurrent.LazyInitializer;
import org.apache.http.Consts;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.stereotype.Component;
import org.thymeleaf.spring4.SpringTemplateEngine;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@Path(ResourcePaths.QUUX_PATH)
public class QuuxResource {
    private static final String GITHUB_OAUTH_ENDPOINT = "https://github.com/login/oauth/authorize";
    private static final String GITHUB_TOKEN_EXCHANGE_ENDPOINT = "https://github.com/login/oauth/access_token";
    private static final String GITHUB_API_ENDPOINT = "https://api.github.com/user";

    private static final String GITHUB_CLIENT_ID = "2e686a63f4ca754067f5";
    private static final String GITHUB_CLIENT_SECRET = "94e4cdbc4aba9ba0f8527767f61fcdd24a76a729";

    private static final String LINKEDIN_OAUTH_ENDPOINT = "https://www.linkedin.com/uas/oauth2/authorization";
    private static final String LINKEDIN_TOKEN_EXCHANGE_ENDPOINT = "https://www.linkedin.com/uas/oauth2/accessToken";
    private static final String LINKEDIN_API_ENDPOINT = "https://api.linkedin.com/v1/people/~";

    private static final String LINKEDIN_CLIENT_ID = "78qwi3o05o45vn";
    private static final String LINKEDIN_CLIENT_SECRET = "ISPKe2mI5H4C0JKB";

    private static final String BBAUTH_CONFIG_ENDPOINT = "https://bbauth-signin-cdev.blackbaudhosting.com";
    private static final String BBAUTH_CLIENT_ID = "mgmsandbox";

    @Inject
    private SpringTemplateEngine templateEngine;

    @Inject
    private JwtSupport jwtSupport;

    @Context
    private UriInfo uriInfo;

    org.thymeleaf.context.Context ctx = new org.thymeleaf.context.Context();

    private enum Idp {
        GITHUB, LINKEDIN, BBAUTH
    }

    private static class BBAuthInitializer extends LazyInitializer<OpenidConnectConfigurationFactory.Config> {
        @Override
        protected OpenidConnectConfigurationFactory.Config initialize() throws ConcurrentException {
            return OpenidConnectConfigurationFactory.getConfig(BBAUTH_CONFIG_ENDPOINT);
        }
    }

    private BBAuthInitializer bbAuthInitializer = new BBAuthInitializer();

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response initialRequest() {
        ctx.clearVariables();

        ArrayList<ResourceBean> allResources = new ArrayList<>();

        allResources.add(ResourceBean.builder().name("Github").value("GITHUB").build());
        allResources.add(ResourceBean.builder().name("LinkedIn").value("LINKEDIN").build());
        allResources.add(ResourceBean.builder().name("BB Auth").value("BBAUTH").build());

        ctx.setVariable("resources", allResources);

        final URI postUri = UriBuilder.fromUri(uriInfo.getBaseUri()).path(QuuxResource.class).path(ResourcePaths.QUUX_CONSUMER_PATH).build();
        ctx.setVariable("postUri", postUri);

        return Response.ok()
                .entity(templateEngine.process("post.template", ctx))
                .build();
    }

    @POST
    @Path(ResourcePaths.QUUX_CONSUMER_PATH)
    @Produces(MediaType.TEXT_HTML)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response getResource(@FormParam("resource") String resource) {
        if (Strings.isNullOrEmpty(resource)) {
            final URI getUri = UriBuilder.fromUri(uriInfo.getBaseUri()).path(QuuxResource.class).build();
            return Response.temporaryRedirect(getUri).build();
        }

        Idp idp = Idp.valueOf(resource);

        // redirect the user to github for auth
        final URI postUri = UriBuilder.fromUri(uriInfo.getBaseUri()).path(QuuxResource.class).path(ResourcePaths.QUUX_CALLBACK_PATH).build();

        URI requestUri = null;
        UUID nonce = UUID.randomUUID();
        JwtSupport.Context context = JwtSupport.Context.builder()
                .resource(resource)
                .nonce(nonce)
                .build();
        switch (idp) {
            case GITHUB:
                try {
                    requestUri = new URIBuilder(GITHUB_OAUTH_ENDPOINT)
                            .setParameter("client_id", GITHUB_CLIENT_ID)
                            .setParameter("redirect_uri", postUri.toString())
                            .setParameter("scope", "user:email,openid")
                            .setParameter("state", jwtSupport.createStateToken(context))
                            .build();
                } catch (URISyntaxException e) {
                    throw new ServerErrorException("unable to build github request", Response.Status.INTERNAL_SERVER_ERROR, e);
                }
                break;
            case LINKEDIN:
                try {
                    requestUri = new URIBuilder(LINKEDIN_OAUTH_ENDPOINT)
                            .setParameter("response_type", "code")
                            .setParameter("client_id", LINKEDIN_CLIENT_ID)
                            .setParameter("redirect_uri", postUri.toString())
                            .setParameter("scope", "r_basicprofile")
                            .setParameter("state", jwtSupport.createStateToken(context))
                            .build();
                } catch (URISyntaxException e) {
                    throw new ServerErrorException("unable to build linkedin request", Response.Status.INTERNAL_SERVER_ERROR, e);
                }
                break;
            case BBAUTH:
                try {
                    requestUri = new URIBuilder(bbAuthInitializer.get().getAuthorizationEndpoint())
                            .setParameter("response_type", "id_token")
                            .setParameter("client_id", BBAUTH_CLIENT_ID)
                            .setParameter("redirect_uri", postUri.toString())
                            .setParameter("scope", "openid email profile")
                            .setParameter("state", jwtSupport.createStateToken(context))
                            .setParameter("nonce", nonce.toString())
                            .build();
                } catch (URISyntaxException | ConcurrentException e) {
                    throw new ServerErrorException("unable to build bbauth request", Response.Status.INTERNAL_SERVER_ERROR, e);
                }
                break;
            default:
                throw new ServerErrorException("unsupported IdP", Response.Status.INTERNAL_SERVER_ERROR);
        }


        log.info(String.format("request uri = %s", requestUri));

        return Response.seeOther(requestUri).build();
    }

    @GET
    @Path(ResourcePaths.QUUX_CALLBACK_PATH)
    public Response handleCallback(@QueryParam("id_token") String idToken, @QueryParam("code") String code, @QueryParam("state") String state) {
        if (idToken == null && code == null && state == null) {
            ctx.clearVariables();

            final URI postUri = UriBuilder.fromUri(uriInfo.getBaseUri()).path(QuuxResource.class).path(ResourcePaths.QUUX_RESULT_PATH).build();

            ctx.setVariable("postUri", postUri.toString());

            return Response.ok()
                    .entity(templateEngine.process("fragment.template", ctx))
                    .build();
        }

        JwtSupport.Context context = jwtSupport.validateStateToken(state);

        // exchange the code for an access token
        String accessToken = getAccessToken(code, state);

        // use the access token to call the github API
        String content = callIdpApi(accessToken, context.getResource());

        return renderResultTemplate(context.getResource(), content);
    }

    private Response renderResultTemplate(String rsc, String content) {
        ctx.clearVariables();

        ctx.setVariable("thing", content);
        ctx.setVariable("resource", rsc);

        return Response.ok()
                .entity(templateEngine.process("result.template", ctx))
                .build();
    }

    @POST
    @Path(ResourcePaths.QUUX_RESULT_PATH)
    public Response handlePostResult(@FormParam("id_token") String idToken, @FormParam("state") String state) {
        JwtSupport.Context context;
        try {
            context = jwtSupport.validateStateToken(state);
            jwtSupport.validateIdToken(idToken, bbAuthInitializer.get(), context);
        } catch (ConcurrentException e) {
            throw new ServerErrorException("unable to retrieve config", Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        return renderResultTemplate(context.getResource(), idToken);
    }


    private String getAccessToken(String code, String state) {
        JwtSupport.Context context = jwtSupport.validateStateToken(state);

        Idp idp = Idp.valueOf(context.getResource());

        final URI postUri = UriBuilder.fromUri(uriInfo.getBaseUri()).path(QuuxResource.class).path(ResourcePaths.QUUX_CALLBACK_PATH).build();

        List<NameValuePair> formParams = new ArrayList<>();

        HttpPost httpPost;

        switch (idp) {
            case GITHUB:
                formParams.add(new BasicNameValuePair("client_id", GITHUB_CLIENT_ID));
                formParams.add(new BasicNameValuePair("client_secret", GITHUB_CLIENT_SECRET));
                formParams.add(new BasicNameValuePair("code", code));
                formParams.add(new BasicNameValuePair("state", state));

                httpPost = new HttpPost(GITHUB_TOKEN_EXCHANGE_ENDPOINT);

                break;
            case LINKEDIN:
                formParams.add(new BasicNameValuePair("grant_type", "authorization_code"));
                formParams.add(new BasicNameValuePair("code", code));
                formParams.add(new BasicNameValuePair("redirect_uri", postUri.toString()));
                formParams.add(new BasicNameValuePair("client_id", LINKEDIN_CLIENT_ID));
                formParams.add(new BasicNameValuePair("client_secret", LINKEDIN_CLIENT_SECRET));

                httpPost = new HttpPost(LINKEDIN_TOKEN_EXCHANGE_ENDPOINT);

                break;

            case BBAUTH:
                log.info("we don't do access tokens for BBAUTH");
                return null;
            default:
                throw new ServerErrorException("unsupported IdP", Response.Status.INTERNAL_SERVER_ERROR);
        }


        UrlEncodedFormEntity urlEncodedFormEntity = new UrlEncodedFormEntity(formParams, Consts.UTF_8);

        httpPost.setEntity(urlEncodedFormEntity);
        httpPost.setHeader("Accept", MediaType.APPLICATION_JSON);

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            CloseableHttpResponse httpResponse = client.execute(httpPost);

            String content = IOUtils.toString(httpResponse.getEntity().getContent());
            log.info(String.format("content = %s", content));

            Map<String, Object> map = new ObjectMapper().readValue(content, Map.class);

            return (String) map.get("access_token");
        } catch (IOException e) {
            throw new ServerErrorException("unable to exchange code for token", Response.Status.INTERNAL_SERVER_ERROR, e);
        }
    }

    private String callIdpApi(String accessToken, String resource) {

        Idp idp = Idp.valueOf(resource);

        HttpGet httpGet;

        switch (idp) {
            case GITHUB:
                httpGet = new HttpGet(GITHUB_API_ENDPOINT);
                httpGet.setHeader("Authorization", String.format("token %s", accessToken));
                break;
            case LINKEDIN:
                httpGet = new HttpGet(LINKEDIN_API_ENDPOINT);
                httpGet.setHeader("Authorization", String.format("Bearer %s", accessToken));
                httpGet.setHeader("x-li-format", "json");
                break;
            case BBAUTH:
                return "{\"message\":\"we don't do api for bbauth\"}";
            default:
                throw new ServerErrorException("unknown IdP", Response.Status.INTERNAL_SERVER_ERROR);
        }

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            httpGet.setHeader("Accept", MediaType.APPLICATION_JSON);

            CloseableHttpResponse httpResponse = client.execute(httpGet);

            String content = IOUtils.toString(httpResponse.getEntity().getContent());
            log.info(String.format("content = %s", content));

            return content;
        } catch (IOException e) {
            throw new ServerErrorException("unable to call github api", Response.Status.INTERNAL_SERVER_ERROR, e);
        }
    }
}
