package com.smockin.admin.service.utils.aws;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class AwsCredentialsProvider {
    private final static Logger logger = LoggerFactory.getLogger(AwsCredentialsProvider.class);

    private final Map<String, String> credentials = new HashMap<>();
    private final AwsProfile defaultProfile;

    public AwsCredentialsProvider(AwsProfileProvider awsProfileProvider) throws IOException {
        this.defaultProfile = awsProfileProvider.findDefaultProfile();
        if (defaultProfile != null) {
            add(defaultProfile);
        }
    }

    public AwsProfile getDefaultProfile() {
        return defaultProfile;
    }

    public final void add(AwsProfile profile) {
        add(profile.getAwsAccessKey(), profile.getAwsSecretKey());
    }

    public final void add(String awsAccessKey, String awsSecretKey) {
        logger.debug("Storing new credentials: [" + awsAccessKey + "]: [" + awsSecretKey + "]");
        credentials.put(awsAccessKey, awsSecretKey);
    }

    public String get(String awsAccessKey) {
        String awsSecretKey = credentials.get(awsAccessKey);
        logger.debug("SecretKey for [" + awsAccessKey + "]: [" + awsSecretKey + "]");
        return awsSecretKey;
    }
}