package com.smockin.admin.service.utils.aws;

public class AwsProfile {

    private final String profile;
    private final String awsAccessKey;
    private final String awsSecretKey;
    private final String region;

    public AwsProfile(String profile, String awsAccessKey, String awsSecretKey, String region) {
        this.profile = profile;
        this.awsAccessKey = awsAccessKey;
        this.awsSecretKey = awsSecretKey;
        this.region = region;
    }

    public String getProfile() {
        return profile;
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
