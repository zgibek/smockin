package com.smockin.admin.service.utils.aws;

import com.smockin.admin.service.utils.aws.auth.AWS4SignerBase;
import com.smockin.admin.service.utils.aws.util.BinaryUtils;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.Date;
import java.util.Map;

/**
 * Based and inspired by:
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-examples-using-sdks.html#sig-v4-examples-using-sdk-java
 */
public class AWS4Signer extends AWS4SignerBase {
    private final Logger logger = LoggerFactory.getLogger(AWS4Signer.class);

    private final String awsAccessKey;
    private final String awsSecretKey;

    /**
     * Create a new AWS V4 signer.
     *
     * @param awsAccessKey The user's AWS Access Key.
     * @param awsSecretKey The user's AWS Secret Key.
     * @param endpointUrl The service endpoint, including the path to any resource.
     * @param httpMethod  The HTTP verb for the request, e.g. GET.
     * @param serviceName The signing name of the service, e.g. 's3'.
     * @param regionName  The system name of the AWS region associated with the
     */
    public AWS4Signer(final String awsAccessKey, final String awsSecretKey,
                      URL endpointUrl, String httpMethod, String serviceName, String regionName) {
        super(endpointUrl, httpMethod, serviceName, regionName);
        this.awsAccessKey = awsAccessKey;
        this.awsSecretKey = awsSecretKey;
        logger.debug("AWS4Signer created for awsAccessKey: " + awsAccessKey);
    }

    /**
     * Computes content hash based on given body (actually, any content).
     *
     * @param body Content for hash calculation
     * @return computed hash or {@link #EMPTY_BODY_SHA256} in case of null or empty body.
     */
    public static String computeContentHash(String body) {
        if (body == null || body.length() == 0) {
            return EMPTY_BODY_SHA256;
        }
        byte[] contentHash = AWS4SignerBase.hash(body);
        return BinaryUtils.toHex(contentHash);
    }

    /**
     * Update headers with body hash, using {@link #HEADER_X_AMZ_CONTENT_SHA_256} name.
     * @param headers Headers to update.
     * @param contentHash Content hash, calculated with {@link #computeContentHash}.
     */
    public static void updateHeaderWithContentHash(Map<String, String> headers, String contentHash) {
        assert headers != null;
        removeHeader(headers, HEADER_X_AMZ_CONTENT_SHA_256);
        headers.put(HEADER_X_AMZ_CONTENT_SHA_256, contentHash);
    }

    /**
     * Removes from headers given header despite the lower/upper case letters.
     * @param headers headers to review.
     * @param header header to remove.
     */
    public static void removeHeader(final Map<String, String> headers, final String header) {
        headers.keySet().removeIf(key -> key.equalsIgnoreCase(header));
    }

    public static void updateHeaderWithAuthorization(Map<String, String> headers, String awsAuthorizationHeaderValue) {
        removeHeader(headers, HttpHeaders.AUTHORIZATION);
        headers.put(HttpHeaders.AUTHORIZATION, awsAuthorizationHeaderValue);
    }

    /**
     * Computes an AWS4 signature for a request, ready for inclusion as an
     * 'Authorization' header.
     *
     * @param headers
     *            The request headers; 'Host' and 'x-amz-date' will be added to
     *            this set.<br/>
     *            1. Should contain {@link #HEADER_X_AMZ_CONTENT_SHA_256} header already.
     *            See {@link #updateHeaderWithContentHash} <br/>
     *            2. Should contain {@link HttpHeaders#HOST} header set already.
     * @param queryParameters
     *            Any query parameters that will be added to the endpoint. The
     *            parameters should be specified in canonical format.
     * @return The computed authorization string for the request. This value
     *         needs to be set as the header 'Authorization' on the subsequent
     *         HTTP request.
     */
    public String computeSignature(Map<String, String> headers,
                                   Map<String, String> queryParameters) {
        // first get the date and time for the subsequent request, and convert
        // to ISO 8601 format for use in signature generation
        Date now = new Date();
        String dateTimeStamp = dateTimeFormat.format(now);

        return computeSignature(headers, queryParameters, dateTimeStamp);
    }

    public String computeSignature(Map<String, String> headers,
                                   Map<String, String> queryParameters, String dateTimeStamp) {

        logger.debug("Computing signature for awsAccessKey: " + awsAccessKey);
        // update the headers with required 'x-amz-date'
        removeHeader(headers, HEADER_X_AMZ_DATE);
        headers.put(HEADER_X_AMZ_DATE, dateTimeStamp);

        // canonicalize the headers; we need the set of header names as well as the
        // names and values to go into the signature process
        String canonicalizedHeaderNames = getCanonicalizeHeaderNames(headers);
        String canonicalizedHeaders = getCanonicalizedHeaderString(headers);

        // if any query string parameters have been supplied, canonicalize them
        String canonicalizedQueryParameters = getCanonicalizedQueryString(queryParameters);

        // use calculated hash value from header
        String bodyHash = headers.get(HEADER_X_AMZ_CONTENT_SHA_256);

        // canonicalize the various components of the request
        String canonicalRequest = getCanonicalRequest(endpointUrl, httpMethod,
                canonicalizedQueryParameters, canonicalizedHeaderNames,
                canonicalizedHeaders, bodyHash);
        logger.debug("--------- Canonical request --------");
        logger.debug(canonicalRequest);
        logger.debug("------------------------------------");

        // construct the string to be signed
        String dateStamp = dateTimeStamp.substring(0, 8);
        String scope =  dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;
        String stringToSign = getStringToSign(SCHEME, ALGORITHM, dateTimeStamp, scope, canonicalRequest);
        logger.debug("--------- String to sign -----------");
        logger.debug(stringToSign);
        logger.debug("------------------------------------");

        // compute the signing key
        byte[] kSecret = (SCHEME + awsSecretKey).getBytes();
        byte[] kDate = sign(dateStamp, kSecret, "HmacSHA256");
        byte[] kRegion = sign(regionName, kDate, "HmacSHA256");
        byte[] kService = sign(serviceName, kRegion, "HmacSHA256");
        byte[] kSigning = sign(TERMINATOR, kService, "HmacSHA256");
        byte[] signature = sign(stringToSign, kSigning, "HmacSHA256");

        String credentialsAuthorizationHeader =
                "Credential=" + awsAccessKey + "/" + scope;
        String signedHeadersAuthorizationHeader =
                "SignedHeaders=" + canonicalizedHeaderNames;
        String signatureAuthorizationHeader =
                "Signature=" + BinaryUtils.toHex(signature);

        String authorizationHeader = SCHEME + "-" + ALGORITHM + " "
                + credentialsAuthorizationHeader + ", "
                + signedHeadersAuthorizationHeader + ", "
                + signatureAuthorizationHeader;

        return authorizationHeader;
    }

}
