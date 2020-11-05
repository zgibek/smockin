package com.smockin.mockserver.engine;

import com.smockin.admin.dto.HttpClientCallDTO;
import com.smockin.admin.dto.response.HttpClientResponseDTO;
import com.smockin.admin.exception.ValidationException;
import com.smockin.admin.persistence.dao.RestfulMockDAO;
import com.smockin.admin.persistence.entity.RestfulMock;
import com.smockin.admin.persistence.entity.RestfulMockDefinitionOrder;
import com.smockin.admin.persistence.entity.RestfulMockDefinitionRule;
import com.smockin.admin.persistence.enums.*;
import com.smockin.admin.service.HttpClientService;
import com.smockin.admin.service.utils.aws.AWS4Signer;
import com.smockin.admin.service.utils.aws.AwsCredentialsProvider;
import com.smockin.admin.service.utils.aws.AwsProfile;
import com.smockin.mockserver.dto.MockedServerConfigDTO;
import com.smockin.mockserver.exception.InboundParamMatchException;
import com.smockin.mockserver.service.*;
import com.smockin.mockserver.service.dto.RestfulResponseDTO;
import com.smockin.utils.GeneralUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spark.Request;
import spark.Response;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Created by mgallina.
 */
@Service
@Transactional(readOnly = true)
public class MockedRestServerEngineUtils {

    private final Logger logger = LoggerFactory.getLogger(MockedRestServerEngineUtils.class);

    private static final String HEADER_X_SMOCKIN_AWS_SERVICE = "x-smockin-aws-service";
    private static final String AWS_S3_SERVICE = "s3";
    private static final String AWS_STS_SERVICE = "sts";
    private static final String ENDPOINT_AMAZONAWS_COM = ".amazonaws.com";
    private static final String ENDPOINT_US_EAST_1_AMAZONAWS_COM = ".us-east-1.amazonaws.com";

    @Autowired
    private RestfulMockDAO restfulMockDAO;

    @Autowired
    private MockOrderingCounterService mockOrderingCounterService;

    @Autowired
    private RuleEngine ruleEngine;

    @Autowired
    private HttpProxyService proxyService;

    @Autowired
    private JavaScriptResponseHandler javaScriptResponseHandler;

    @Autowired
    private InboundParamMatchService inboundParamMatchService;

    @Autowired
    private ServerSideEventService serverSideEventService;

    @Autowired
    private StatefulService statefulService;

    @Autowired
    private HttpClientService httpClientService;

    @Autowired
    private AwsCredentialsProvider awsCredentialsProvider;


    public Optional<String> loadMockedResponse(final Request request,
                                               final Response response,
                                               final boolean isMultiUserMode,
                                               final MockedServerConfigDTO config) {

        logger.debug("loadMockedResponse called");

        debugInboundRequest(request);

        final Optional<String> opMockedResponse = (config.isProxyMode() && !isMultiUserMode)
                ? handleProxyInterceptorMode(config,
                request,
                response)
                : handleMockLookup(request, response, isMultiUserMode, false);
        opMockedResponse.ifPresent(mockedResponse -> {
            logger.debug("===========================================================================\n" +
                    "Got response from mocked/proxy:\n"+
                    mockedResponse + "\n" +
                    "===========================================================================");
            if (mockedResponse != null && mockedResponse.startsWith("<AssumeRoleResponse ")) {
                Pattern accessKeyPattern = Pattern.compile("<AccessKeyId>(.*)</AccessKeyId>");
                Pattern secretKeyPattern = Pattern.compile("<SecretAccessKey>(.*)</SecretAccessKey>");
                Matcher accessKeyMatcher = accessKeyPattern.matcher(mockedResponse);
                Matcher secretKeyMatcher = secretKeyPattern.matcher(mockedResponse);
                if (accessKeyMatcher.find() && secretKeyMatcher.find()) {
                    awsCredentialsProvider.add(accessKeyMatcher.group(1), secretKeyMatcher.group(1));
                }
            }
        });
        return opMockedResponse;
    }

    Optional<String> handleMockLookup(final Request request,
                           final Response response,
                           final boolean isMultiUserMode,
                           final boolean ignore404MockResponses) {
        logger.debug("handleMockLookup called");

        try {

            final RestfulMock mock = (isMultiUserMode)
                    ? restfulMockDAO.findActiveByMethodAndPathPatternAndTypesForMultiUser(
                    RestMethodEnum.findByName(request.requestMethod()),
                    request.pathInfo(),
                    Arrays.asList(RestMockTypeEnum.PROXY_SSE,
                            RestMockTypeEnum.PROXY_HTTP,
                            RestMockTypeEnum.SEQ,
                            RestMockTypeEnum.RULE,
                            RestMockTypeEnum.STATEFUL,
                            RestMockTypeEnum.CUSTOM_JS))
                    : restfulMockDAO.findActiveByMethodAndPathPatternAndTypesForSingleUser(
                    RestMethodEnum.findByName(request.requestMethod()),
                    request.pathInfo(),
                    Arrays.asList(RestMockTypeEnum.PROXY_SSE,
                            RestMockTypeEnum.PROXY_HTTP,
                            RestMockTypeEnum.SEQ,
                            RestMockTypeEnum.RULE,
                            RestMockTypeEnum.STATEFUL,
                            RestMockTypeEnum.CUSTOM_JS));

            if (mock == null) {
                logger.debug("no mock was found");
                return Optional.empty();
            }

            debugLoadedMock(mock);

            if (RestMockTypeEnum.PROXY_SSE.equals(mock.getMockType())) {
                return Optional.of(processSSERequest(mock, request, response));
            }

            removeSuspendedResponses(mock);

            final String responseBody = processRequest(mock, request, response, ignore404MockResponses);

            // Yuk! Bit of a hacky work around returning null from processRequest, so as to distinguish an ignored 404...
            return (responseBody != null)
                    ? Optional.of(responseBody)
                    : Optional.empty();

        } catch (Exception ex) {
            return handleFailure(ex, response);
        }

    }

    Optional<String> handleProxyInterceptorMode(final MockedServerConfigDTO config,
                                                final Request request,
                                                final Response response) {
        final ProxyModeTypeEnum proxyModeType = config.getProxyModeType();
        final String proxyForwardUrl = config.getProxyForwardUrl();
        final boolean doNotForwardWhen404Mock = config.isDoNotForwardWhen404Mock();
        final ProxyHeaderHostModeEnum proxyHeaderHostMode = config.getProxyHeaderHostMode();
        final String proxyFixedHeaderHost = config.getProxyFixedHeaderHost();

        logger.debug("handleProxyInterceptorMode called");

        try {

            if (StringUtils.isBlank(proxyForwardUrl)) {
                throw new Exception("Unable to use proxy mode. Proxy Forwarding Url is undefined");
            }

            if (ProxyModeTypeEnum.ACTIVE.equals(proxyModeType)) {

                // Look for mock...
                final Optional<String> result = handleMockLookup(request, response, false, !doNotForwardWhen404Mock);

                if (result.isPresent()) {
                    return result;
                }

                // Make downstream client call of no mock was found
                return handleClientDownstreamProxyCallResponse(executeClientDownstreamProxyCall(proxyForwardUrl, proxyHeaderHostMode, proxyFixedHeaderHost, request), response);
            }

            // Default to REACTIVE mode...

            final HttpClientResponseDTO httpClientResponse = executeClientDownstreamProxyCall(proxyForwardUrl, proxyHeaderHostMode, proxyFixedHeaderHost, request);

            if (HttpStatus.NOT_FOUND.value() == httpClientResponse.getStatus()) {

                // Look for mock substitute if downstream client returns a 404
                return handleMockLookup(request, response, false, false);
            }

            // Pass back downstream client response directly back to caller
            return handleClientDownstreamProxyCallResponse(httpClientResponse, response);

        } catch (Exception ex) {
            return handleFailure(ex, response);
        }

    }

    HttpClientResponseDTO executeClientDownstreamProxyCall(final String proxyForwardUrl,
                                                           final ProxyHeaderHostModeEnum proxyHeaderHostMode,
                                                           final String proxyFixedHeaderHost,
                                                           final Request request)
            throws ValidationException {

        if (logger.isDebugEnabled()) {
            logger.debug("Initiating proxied call to downstream client: " + proxyForwardUrl + request.pathInfo());
        }


        final HttpClientCallDTO httpClientCallDTO = new HttpClientCallDTO();
        final String reqParams = (request.queryString() != null)
                ? ( "?" + request.queryString() )
                : "";
        httpClientCallDTO.setUrl(proxyForwardUrl + request.pathInfo() + reqParams);
        httpClientCallDTO.setPathInfo(request.pathInfo());
        httpClientCallDTO.setRequestParams(reqParams);
        httpClientCallDTO.setMethod(RestMethodEnum.valueOf(request.requestMethod()));
        httpClientCallDTO.setBody(request.body());

        httpClientCallDTO.setHeaders(request
                .headers()
                .stream()
                .collect(Collectors.toMap(k -> k, v -> request.headers(v))));

        // adapt headers for AWS
        adaptRequestForAWS(proxyForwardUrl, proxyHeaderHostMode, proxyFixedHeaderHost, httpClientCallDTO);

        return httpClientService.handleExternalCall(httpClientCallDTO);
    }

    private void adaptRequestForAWS(String proxyForwardUrl, ProxyHeaderHostModeEnum proxyHeaderHostMode, String proxyFixedHeaderHost, HttpClientCallDTO httpClientCallDTO) {
        String downstreamHost = StringUtils.remove(proxyForwardUrl, HttpClientService.HTTPS_PROTOCOL);
        downstreamHost = StringUtils.remove(downstreamHost, HttpClientService.HTTP_PROTOCOL);

        final boolean isAwsServiceCall = isAwsServiceCall(httpClientCallDTO);

        String hostForHeader = determineHeaderHostValue(
                isAwsServiceCall,
                proxyHeaderHostMode,
                httpClientCallDTO,
                downstreamHost,
                proxyFixedHeaderHost);
        logger.debug("Using header.Host {}, based on mode: {}, real value from request {} and downstream URL {}",
                hostForHeader, proxyHeaderHostMode, httpClientCallDTO.getHeaders().get(HttpHeaders.HOST), proxyForwardUrl);
        AWS4Signer.removeHeader(httpClientCallDTO.getHeaders(), HttpHeaders.HOST);
        httpClientCallDTO.getHeaders().put(HttpHeaders.HOST, hostForHeader);
        final boolean isAwsCall = hostForHeader.endsWith("amazonaws.com");

        if (isAwsServiceCall) {
            final String service = httpClientCallDTO.getHeaders().get(HttpHeaders.HOST);
            httpClientCallDTO.setUrl("https://" + hostForHeader + httpClientCallDTO.getPathInfo() + httpClientCallDTO.getRequestParams());
            try {
                AwsProfile awsProfile = awsCredentialsProvider.getDefaultProfile();
                final String awsAccessKey = determineAwsAccessKeyBasedOnRequest(httpClientCallDTO.getHeaders());
                AWS4Signer aws4Signer = new AWS4Signer(awsAccessKey, awsCredentialsProvider.get(awsAccessKey),
                        new URL(httpClientCallDTO.getUrl()), httpClientCallDTO.getMethod().toString(),
                        httpClientCallDTO.getHeaders().get(HEADER_X_SMOCKIN_AWS_SERVICE).toLowerCase(),
                        awsProfile.getRegion()
                );
                AWS4Signer.removeHeader(httpClientCallDTO.getHeaders(), HEADER_X_SMOCKIN_AWS_SERVICE);
                final String bodyHash = AWS4Signer.computeContentHash(httpClientCallDTO.getBody());
                AWS4Signer.updateHeaderWithContentHash(httpClientCallDTO.getHeaders(), bodyHash);
                String signature = aws4Signer.computeSignature(httpClientCallDTO.getHeaders(), null);
                AWS4Signer.updateHeaderWithAuthorization(httpClientCallDTO.getHeaders(), signature);
            } catch (MalformedURLException urlException) {
                logger.error("Cannot construct endpoint for " + service, urlException);
            }
            httpClientCallDTO.getHeaders().remove(HttpHeaders.CONTENT_LENGTH);
        } else if (isAwsCall) {
            httpClientCallDTO.getHeaders().remove(HttpHeaders.CONTENT_LENGTH);
            httpClientCallDTO.setUrl("https://" + hostForHeader
                    + httpClientCallDTO.getPathInfo() + httpClientCallDTO.getRequestParams()
            );
        };
    }

    private String determineAwsAccessKeyBasedOnRequest(Map<String, String> headers) {
        String accessKey = null;
        if (headers != null && headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            String authHeader = headers.get(HttpHeaders.AUTHORIZATION);
            if (authHeader.startsWith("AWS4-HMAC-SHA256 Credential=")) {
                Matcher matcher = Pattern.compile("AWS4-HMAC-SHA256 Credential=([^/]*)/").matcher(authHeader);
                if (matcher.find() && matcher.groupCount() == 1) {
                    accessKey = matcher.group(1);
                    logger.debug("Determined awsAccessKey based on Authorization header: " + accessKey);
                }
            }
        }

        if (awsCredentialsProvider.get(accessKey) == null) {
            logger.debug("AWSCredentials can't find secret for " + accessKey + " -> using the one from profile");
            accessKey = null;
        }

        if (accessKey == null) {
            AwsProfile profile = awsCredentialsProvider.getDefaultProfile();
            accessKey = profile.getAwsAccessKey();
        }
        return accessKey;
    }

    private boolean isAwsServiceCall(HttpClientCallDTO httpClientCallDTO) {
        final String authHeader = httpClientCallDTO.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) {
            return false;
        }
        final boolean isAwsService = authHeader.startsWith("AWS4-HMAC-SHA256 ");
        if (isAwsService) {
            logger.debug("AWS Service call detected for: " + httpClientCallDTO.getBody());
        }
        return isAwsService;
    }

    String determineHeaderHostValue(boolean isAwsServiceCall, ProxyHeaderHostModeEnum proxyHeaderHostMode, HttpClientCallDTO httpClientCallDTO, String downstreamHost, String proxyFixedHeaderHost) {
        final String proxyFromRequest = httpClientCallDTO.getHeaders().get(HttpHeaders.HOST);
        switch (proxyHeaderHostMode) {
            case FIXED:
                return proxyFixedHeaderHost;
            case FROM_REQUEST:
                 return proxyFromRequest == null ? downstreamHost : proxyFromRequest;
            case SMART:
                if (isAwsServiceCall) {
                    final String pathInfo = httpClientCallDTO.getPathInfo();
                    final Matcher serviceMatcher = Pattern.compile("/aws-service-([a-zA-Z0-9]*).*").matcher(pathInfo);
                    final String awsService;
                    if (serviceMatcher.find() && serviceMatcher.groupCount() >= 1) {
                        awsService = serviceMatcher.group(1).toLowerCase();
                        AWS4Signer.removeHeader(httpClientCallDTO.getHeaders(), HEADER_X_SMOCKIN_AWS_SERVICE);
                        httpClientCallDTO.getHeaders().put(HEADER_X_SMOCKIN_AWS_SERVICE, awsService);
                        httpClientCallDTO.setPathInfo("/");
                        return determineEndpointForService(awsService);
                    }
                    logger.error("Can't map AWS service for path: " + pathInfo);
                    return "";
                } else if (!downstreamHost.endsWith("amazonaws.com")) {
                    return downstreamHost;
                }
                return proxyFromRequest == null ? downstreamHost : proxyFromRequest;
        }
        return downstreamHost;
    }

    public static String determineEndpointForService(String awsService) {
        switch (awsService) {
            case AWS_S3_SERVICE:
            case AWS_STS_SERVICE:
                return awsService + ENDPOINT_AMAZONAWS_COM;
            default:
                return awsService + ENDPOINT_US_EAST_1_AMAZONAWS_COM;
        }
    }

    Optional<String> handleClientDownstreamProxyCallResponse(final HttpClientResponseDTO httpClientResponse,
                                           final Response response) throws ValidationException {

        if (logger.isDebugEnabled()) {
            logger.debug("Downstream client response status: " + httpClientResponse.getStatus());
        }

        response.status(httpClientResponse.getStatus());
        response.type(httpClientResponse.getContentType());
        response.body(httpClientResponse.getBody());

        httpClientResponse.getHeaders()
                .entrySet()
                .forEach(e ->
                        response.header(e.getKey(), e.getValue()));

        response.header(GeneralUtils.PROXIED_RESPONSE_HEADER, Boolean.TRUE.toString());

        return Optional.of(StringUtils.defaultIfBlank(httpClientResponse.getBody(),""));
    }

    String processRequest(final RestfulMock mock,
                          final Request req,
                          final Response res,
                          final boolean ignore404MockResponses) {
        logger.debug("processRequest called for mock: " + mock.getPath());
        RestfulResponseDTO outcome;

        switch (mock.getMockType()) {
            case RULE:
                outcome = ruleEngine.process(req, mock.getRules());
                break;
            case PROXY_HTTP:
                outcome = proxyService.waitForResponse(req.pathInfo(), mock);
                break;
            case CUSTOM_JS:
                outcome = javaScriptResponseHandler.executeUserResponse(req, mock);
                break;
            case STATEFUL:
                outcome = statefulService.process(req, mock);
                break;
            case SEQ:
            default:
                outcome = mockOrderingCounterService.process(mock);
                break;
        }

        if (outcome == null) {
            // Load in default values
            outcome = getDefault(mock);
        }
        if (ignore404MockResponses
                        && HttpStatus.NOT_FOUND.value() == outcome.getHttpStatusCode()) {
            // Yuk! Bit of a hacky work around returning null so as to distinguish an ignored 404...
            return null;
        }

        debugOutcome(outcome);

        res.status(outcome.getHttpStatusCode());
        res.type(outcome.getResponseContentType());

        // Apply any response headers
        outcome.getHeaders()
                .entrySet()
                .forEach(e ->
                            res.header(e.getKey(), e.getValue()));

        String response;

        try {
            response = inboundParamMatchService.enrichWithInboundParamMatches(req, mock.getPath(), outcome.getResponseBody(), mock.getCreatedBy().getCtxPath(), mock.getCreatedBy().getId());
            handleLatency(mock);
        } catch (InboundParamMatchException e) {
            logger.error(e.getMessage());
            res.status(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response = e.getMessage();
        }

        if (logger.isDebugEnabled()) {
            logger.debug("final response " + response);
        }

        return StringUtils.defaultIfBlank(response,"");
    }

    RestfulResponseDTO getDefault(final RestfulMock restfulMock) {
        logger.debug("getDefault called");

        if (RestMockTypeEnum.PROXY_HTTP.equals(restfulMock.getMockType())) {
            return new RestfulResponseDTO(HttpStatus.NOT_FOUND.value());
        }

        final RestfulMockDefinitionOrder mockDefOrder = restfulMock.getDefinitions().get(0);
        return new RestfulResponseDTO(mockDefOrder.getHttpStatusCode(), mockDefOrder.getResponseContentType(), mockDefOrder.getResponseBody(), mockDefOrder.getResponseHeaders().entrySet());
    }

    void removeSuspendedResponses(final RestfulMock mock) {
        logger.debug("removeSuspendedResponses called");

        final Iterator<RestfulMockDefinitionOrder> definitionsIter = mock.getDefinitions().iterator();

        while (definitionsIter.hasNext()) {
            final RestfulMockDefinitionOrder d = definitionsIter.next();

            if (d.isSuspend()) {
                definitionsIter.remove();
            }
        }

        final Iterator<RestfulMockDefinitionRule> rulesIter =  mock.getRules().iterator();

        while (rulesIter.hasNext()) {
            final RestfulMockDefinitionRule r = rulesIter.next();

            if (r.isSuspend()) {
                rulesIter.remove();
            }
        }

    }

    String processSSERequest(final RestfulMock mock, final Request req, final Response res) {

        try {
            serverSideEventService.register(buildUserPath(mock), mock.getSseHeartBeatInMillis(), mock.isProxyPushIdOnConnect(), req, res);
        } catch (IOException e) {
            logger.error("Error registering SEE client", e);
        }

        return "";
    }

    private void handleLatency(final RestfulMock mock) {

        if (!mock.isRandomiseLatency()) {
            return;
        }

        long min = (mock.getRandomiseLatencyRangeMinMillis() > 0) ? mock.getRandomiseLatencyRangeMinMillis() : 1000;
        long max = (mock.getRandomiseLatencyRangeMaxMillis() > 0) ? mock.getRandomiseLatencyRangeMaxMillis() : 5000;

        try {
            Thread.sleep(RandomUtils.nextLong(min, (max + 1)));
        } catch (InterruptedException ex) {
            logger.error("Failed to apply randomised latency and prolong current thread execution", ex);
        }

    }

    public String buildUserPath(final RestfulMock mock) {

        if (!SmockinUserRoleEnum.SYS_ADMIN.equals(mock.getCreatedBy().getRole())) {
            return File.separator + mock.getCreatedBy().getCtxPath() + mock.getPath();
        }

        return mock.getPath();
    }

    Optional<String> handleFailure(final Exception ex, final Response response) {
        logger.error("Error processing mock request", ex);

        response.status(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.body((ex instanceof IllegalArgumentException) ? ex.getMessage() : "Oops, looks like something went wrong with this mock!");

        return Optional.of("Oops"); // this message does not come through to caller when it is a 500 for some reason, so setting in body above

    }

    private void debugInboundRequest(final Request request) {

        if (logger.isDebugEnabled()) {

            logger.debug("inbound request url: " + request.url());
            logger.debug("inbound request query string : " + request.queryString());
            logger.debug("inbound request method: " + request.requestMethod());
            logger.debug("inbound request path: " + request.pathInfo());
            logger.debug("inbound request body: " + request.body());

            request.headers()
                .stream()
                .forEach(h ->
                    logger.debug("inbound request header: " + h + " = " + request.headers(h)));
        }

    }

    private void debugLoadedMock(final RestfulMock mock) {

        if (logger.isDebugEnabled()) {

            logger.debug("mock ext id: " + mock.getExtId());
            logger.debug("mock method: " + mock.getMethod());
            logger.debug("mock path: " + mock.getPath());
            logger.debug("mock type: " + mock.getMockType());

        }

    }

    private void debugOutcome(final RestfulResponseDTO outcome) {

        if (logger.isDebugEnabled()) {

            logger.debug("status " + outcome.getHttpStatusCode());
            logger.debug("content type " + outcome.getResponseContentType());
            logger.debug("status " + outcome.getHttpStatusCode());
            logger.debug("response body " + outcome.getResponseBody());

        }

    }

}
