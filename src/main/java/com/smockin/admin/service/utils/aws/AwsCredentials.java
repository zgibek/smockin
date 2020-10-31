package com.smockin.admin.service.utils.aws;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.TreeMap;

/**
 * Stores credentials - both initial and temporary (via assumeRole) ones.
 *
 * zgibek on 2020-10-31 03:29
 */
public class AwsCredentials {
    private final static Logger logger = LoggerFactory.getLogger(AwsCredentials.class);

    private static TreeMap<String, String> credentials;

    private AwsCredentials() {
    }

    static {
        credentials = new TreeMap<>();
        final AwsProfile awsProfile = new AwsProfile();
        add(awsProfile.getAwsAccessKey(), awsProfile.getAwsSecretKey());
    }

    public static void add(String awsAccessKey, String awsSecretKey) {
        logger.debug("Storing new credentials: [" + awsAccessKey + "]: [" + awsSecretKey + "]");
        credentials.put(awsAccessKey, awsSecretKey);
    }

    public static String getSecretKeyFor(String awsAccessKey) {
        String awsSecretKey = credentials.get(awsAccessKey);
        logger.debug("SecretKey for [" + awsAccessKey + "]: [" + awsSecretKey + "]");
        return awsSecretKey;
    }
}
