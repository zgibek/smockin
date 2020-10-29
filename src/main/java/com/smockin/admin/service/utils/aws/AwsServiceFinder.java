package com.smockin.admin.service.utils.aws;

import java.util.*;

/**
 * Helps decoding (and finding) AWS Service based on action.
 * <p/>
 * AWS proxied call is done to one endpoint, while AWS uses different endpoints for different services.
 * This class tries to differentiate them based on request, for example Action send in Body.
 *
 * @author zgibek on 2020-10-29 07:06
 */
public class AwsServiceFinder {

    /** STS Actions */
    private static Set<String> stsActions = new HashSet<>(Arrays.asList(
            "GetCallerIdentity"
    ));

    /** CostExplorer Actions */
    private static Set<String> ceActions = new HashSet<>(Arrays.asList(
            "GetReservationCoverage",
            "GetReservationPurchaseRecommendation",
            "AWSInsightsIndexService.GetReservationUtilization"
    ));

    /** EC2 Actions */
    private static Set<String> ec2Actions = new HashSet<>(Arrays.asList(
            "AcceptReservedInstancesExchangeQuote",
            "DescribeInstances",
            "DescribeRegions",
            "DescribeReservedInstances",
            "DescribeReservedInstancesListings",
            "DescribeReservedInstancesModifications",
            "DescribeReservedInstancesOfferings",
            "GetReservedInstancesExchangeQuote",
            "ModifyReservedInstances",
            "PurchaseReservedInstancesOffering"
    ));

    public static String findEndpointForService(AwsService awsService) {
        switch (awsService) {
            case STS: return "sts.us-east-1.amazonaws.com";
            case CE: return "ce.us-east-1.amazonaws.com";
            case EC2: return "ec2.us-east-1.amazonaws.com";
        }
        return "";
    }

    public enum AwsService {
        STS,
        CE,
        EC2,
    }

    private static Map<AwsService, Set<String>> serviceActions = new HashMap<AwsService, Set<String>>() {{
        put(AwsService.STS, stsActions);
        put(AwsService.CE, ceActions);
        put(AwsService.EC2, ec2Actions);
    }};

    public static AwsService findServiceForAction(String awsAction) {
        if (awsAction == null) {
            return null;
        }
        for (AwsService awsService : serviceActions.keySet()) {
            if (serviceActions.get(awsService).contains(awsAction)) {
                return awsService;
            }
        }
        return null;
    }
}
