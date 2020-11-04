package com.smockin.admin.service;

import com.smockin.admin.dto.HttpClientCallDTO;
import com.smockin.admin.dto.response.HttpClientResponseDTO;
import com.smockin.admin.exception.ValidationException;
import com.smockin.mockserver.dto.MockServerState;
import com.smockin.mockserver.exception.MockServerException;
import com.smockin.utils.HttpClientUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.methods.*;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by mgallina.
 */
@Service
public class HttpClientServiceImpl implements HttpClientService {

    private final Logger logger = LoggerFactory.getLogger(HttpClientServiceImpl.class);

    @Autowired
    private MockedServerEngineService mockedServerEngineService;

    @Override
    public HttpClientResponseDTO handleExternalCall(final HttpClientCallDTO dto) throws ValidationException {
        logger.debug("handleExternalCall called");

        debugDTO(dto);
        validateRequest(dto);

        try {

            switch (dto.getMethod()) {
                case GET:
                    return get(dto);
                case POST:
                    return post(dto);
                case PUT:
                    return put(dto);
                case DELETE:
                    return delete(dto);
                case PATCH:
                    return patch(dto);
                default:
                    throw new ValidationException("Invalid / Unsupported method: " + dto.getMethod());
            }

        } catch (IOException | MockServerException ex) {
            return new HttpClientResponseDTO(HttpStatus.NOT_FOUND.value());
        }

    }

    @Override
    public HttpClientResponseDTO handleCallToMock(final HttpClientCallDTO dto) throws ValidationException {
        logger.debug("handleCallToMock called");

        debugDTO(dto);

        validateRequest(dto);

        try {

            final MockServerState state = mockedServerEngineService.getRestServerState();

            if (!state.isRunning()) {
                return new HttpClientResponseDTO(HttpStatus.NOT_FOUND.value());
            }

            dto.setUrl("http://localhost:" + state.getPort() + dto.getUrl());

            switch (dto.getMethod()) {
                case GET:
                    return get(dto);
                case POST:
                    return post(dto);
                case PUT:
                    return put(dto);
                case DELETE:
                    return delete(dto);
                case PATCH:
                    return patch(dto);
                default:
                    throw new ValidationException("Invalid / Unsupported method: " + dto.getMethod());
            }

        } catch (IOException | MockServerException ex) {
            return new HttpClientResponseDTO(HttpStatus.NOT_FOUND.value());
        }

    }

    boolean isHttps(final String url) {
        return StringUtils.startsWith(url, HTTPS_PROTOCOL);
    }

    HttpClientResponseDTO get(final HttpClientCallDTO reqDto) throws IOException {

        final Request request = Request.Get(reqDto.getUrl());

        return executeRequest(request, reqDto.getHeaders(), isHttps(reqDto.getUrl()));
    }

    HttpClientResponseDTO post(final HttpClientCallDTO reqDto) throws IOException {

        final Request request = Request.Post(reqDto.getUrl());

        HttpClientUtils.handleRequestData(request, reqDto.getHeaders(), reqDto);

        return executeRequest(request, reqDto.getHeaders(), isHttps(reqDto.getUrl()));
    }

    HttpClientResponseDTO put(final HttpClientCallDTO reqDto) throws IOException {

        final Request request = Request.Put(reqDto.getUrl());

        HttpClientUtils.handleRequestData(request, reqDto.getHeaders(), reqDto);

        return executeRequest(request, reqDto.getHeaders(), isHttps(reqDto.getUrl()));
    }

    HttpClientResponseDTO delete(final HttpClientCallDTO reqDto) throws IOException {

        final Request request = Request.Delete(reqDto.getUrl());

        return executeRequest(request, reqDto.getHeaders(), isHttps(reqDto.getUrl()));
    }

    HttpClientResponseDTO patch(final HttpClientCallDTO reqDto) throws IOException {

        final Request request = Request.Patch(reqDto.getUrl())
                .bodyByteArray((reqDto.getBody() != null)?reqDto.getBody().getBytes():null);

        return executeRequest(request, reqDto.getHeaders(), isHttps(reqDto.getUrl()));
    }

    /**
     *
     * Assumes the request body is not mandatory.
     *
     * @param httpClientCallDTO
     * @throws ValidationException
     *
     */
    void validateRequest(final HttpClientCallDTO httpClientCallDTO) throws ValidationException {

        if (StringUtils.isBlank(httpClientCallDTO.getUrl())) {
            throw new ValidationException("url is required");
        }

        if (httpClientCallDTO.getMethod() == null) {
            throw new ValidationException("method is required");
        }

    }

    void applyRequestHeaders(final Request request, final Map<String, String> requestHeaders) {

        if (requestHeaders == null)
            return;

        requestHeaders
            .entrySet()
            .forEach(h ->
                request.addHeader(h.getKey(), h.getValue()));

    }

    Map<String, String> extractResponseHeaders(final HttpResponse httpResponse) {

        return new HashMap<String, String>() {
            {
                for (Header h : httpResponse.getAllHeaders()) {
                    put(h.getName(), h.getValue());
                }
            }
        };
    }

    String extractResponseBody(final HttpResponse httpResponse) throws IOException {

        return IOUtils.toString(httpResponse.getEntity().getContent(), StandardCharsets.UTF_8.name());
    }

    HttpClientResponseDTO executeRequest(final Request request, final Map<String, String> requestHeaders, final boolean isHttpsCall) throws IOException {


        applyRequestHeaders(request, requestHeaders);

        final HttpResponse httpResponse;

        if (isHttpsCall) {

            try {
                final Executor executor = Executor.newInstance(noSslHttpClient());
                httpResponse = executor.execute(request).returnResponse();
            } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
                throw new IOException();
            }

        } else {
            logger.debug("Request just before execute: " + request.toString());
            httpResponse = request.execute().returnResponse();
        }

        return new HttpClientResponseDTO(
                httpResponse.getStatusLine().getStatusCode(),
                httpResponse.getEntity().getContentType().getValue(),
                extractResponseHeaders(httpResponse),
                extractResponseBody(httpResponse)
        );
    }

    private CloseableHttpClient noSslHttpClient() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

        final SSLContext sslContext = new SSLContextBuilder()
                .loadTrustMaterial(null, (x509CertChain, authType) -> true)
                .build();

        return HttpClientBuilder.create()
                .setSSLContext(sslContext)
                .setConnectionManager(
                        new PoolingHttpClientConnectionManager(
                                RegistryBuilder.<ConnectionSocketFactory>create()
                                        .register("http", PlainConnectionSocketFactory.INSTANCE)
                                        .register("https", new SSLConnectionSocketFactory(sslContext,
                                                NoopHostnameVerifier.INSTANCE))
                                        .build()
                        ))
                .setRedirectStrategy(new RedirectAllowingRedirectStrategy())
                .setRedirectStrategy(new LaxRedirectStrategy())
                .build();
    }

    private class RedirectAllowingRedirectStrategy extends DefaultRedirectStrategy {
        private final String[] REDIRECT_METHODS = new String[] {
                HttpGet.METHOD_NAME,
                HttpPost.METHOD_NAME,
                HttpHead.METHOD_NAME,
                HttpDelete.METHOD_NAME
        };

        @Override
        protected boolean isRedirectable(final String method) {
            for (final String m: REDIRECT_METHODS) {
                if (m.equalsIgnoreCase(method)) {
                    return true;
                }
            }
            return false;
        }
        public boolean isRedirected(HttpRequest request, HttpResponse response, HttpContext context)  {
            boolean isRedirect=false;
            try {
                isRedirect = super.isRedirected(request, response, context);
            } catch (ProtocolException e) {
                e.printStackTrace();
            }
            if (!isRedirect) {
                int responseCode = response.getStatusLine().getStatusCode();
                if (responseCode == 301 || responseCode == 302) {
                    return true;
                }
            }
            return isRedirect;
        }

        @Override
        public HttpUriRequest getRedirect(
                final HttpRequest request,
                final HttpResponse response,
                final HttpContext context) throws ProtocolException {
            final URI uri = getLocationURI(request, response, context);
            final String method = request.getRequestLine().getMethod();
            String message = "======================================================================"
                    +"\nDoing redirection for request: " + request.toString()
                    +"\nResponse: " + response.getStatusLine().getStatusCode() + ": " + response.toString()
                    +"\nContext: " + context
                    +"\n======================================================================";
            logger.info(message);
            if (method.equalsIgnoreCase(HttpHead.METHOD_NAME)) {
                return new HttpHead(uri);
            } else if (method.equalsIgnoreCase(HttpGet.METHOD_NAME)) {
                return new HttpGet(uri);
            } else if (method.equalsIgnoreCase(HttpPost.METHOD_NAME)) {
                return new HttpPost(uri);
            } else {
                final int status = response.getStatusLine().getStatusCode();
                if (status == org.apache.http.HttpStatus.SC_TEMPORARY_REDIRECT) {
                    return RequestBuilder.copy(request).setUri(uri).build();
                } else {
                    return new HttpGet(uri);
                }
            }
        }
    }

    private void debugDTO(final HttpClientCallDTO dto) {

        if (logger.isDebugEnabled()) {
            logger.debug( "URL : " + dto.getUrl() );
            logger.debug( "METHOD : " + dto.getMethod().name() );
            logger.debug( "BODY : " + dto.getBody() );
            logger.debug( "HEADERS : " );

            dto.getHeaders().entrySet().forEach(h ->
                    logger.debug( h.getKey() +  " : " + h.getValue() ));
        }

    }

}
