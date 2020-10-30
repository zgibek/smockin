package com.smockin.admin.service.utils.aws;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Loads AWS credentials from standard file {@link #AWS_CREDENTIALS_FILE}
 * <p/>
 * Profiles can be specified, default is used.
 * Last definition in given profile wins (is returned)
 * <p/>
 *
 * zgibek on 2020-10-29 08:44
 */
public class AwsProfile {
    private final Logger logger = LoggerFactory.getLogger(AwsProfile.class);

    private static final String AWS_CREDENTIALS_FILE = System.getProperty("user.home") + "/.aws/credentials";
    private String awsAccessKey;
    private String awsSecretKey;
    private String region;

    public AwsProfile() {
        this("default");
    }

    public AwsProfile(String profile) {
        Properties profileProperties = new Properties();
        try {
            profileProperties.load(getProfileData(profile));
            awsAccessKey = profileProperties.getProperty("aws_access_key_id");
            awsSecretKey = profileProperties.getProperty("aws_secret_access_key");
            region = profileProperties.getProperty("region");
        } catch (Exception exception) {
            logger.error("Cannot find profile [" + profile + "] in " + AWS_CREDENTIALS_FILE, exception);
        }
    }

    private static Reader getProfileData(String profile) throws IOException {
        LineNumberReader  lineReader = new LineNumberReader(new FileReader(AWS_CREDENTIALS_FILE));
        String line;
        StringBuilder outputProfile = new StringBuilder();
        boolean requestedProfile = false;
        final Pattern profileDefinitionPattern = Pattern.compile("^\\[([^\\]]*)]$");
        while ((line = lineReader.readLine()) != null) {
            Matcher matcher = profileDefinitionPattern.matcher(line);
            if (matcher.find() && matcher.groupCount() >= 1) {
                requestedProfile = profile.equalsIgnoreCase(matcher.group(1));
                continue;
            }
            if (requestedProfile && line.trim().length()>0 && line.contains("=")) {
                outputProfile.append(line).append('\n');
            }
        }
        System.out.println("constructed profile: \n" + outputProfile);

        return new StringReader(outputProfile.toString());
    }

    public String getAwsAccessKey() {
        return awsAccessKey;
    }

    public String getAwsSecretKey() {
        return awsSecretKey;
    }

    public String getRegion() {
        return region;
    }

}
