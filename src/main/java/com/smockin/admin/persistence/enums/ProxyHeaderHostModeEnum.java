package com.smockin.admin.persistence.enums;

/**
 * zgibek on 25/10/2020 22:07
 */
public enum ProxyHeaderHostModeEnum {
    /**
     * Legacy, standard, mode - always from PROXY_FORWARD_URL, AKA Downstream Forwarding URL
     */
    DOWNSTREAM,
    /**
     * FROM_REQUEST if PROXY_FORWARD_URL is amazon AWS services, DOWNSTREAM otherwise
     */
    SMART,
    /**
     * Always from request's header (if set, DOWNSTREAM otherwise)
     */
    FROM_REQUEST,
    /**
     * Always from custom config field PROXY_FIXED_HEADER_HOST
     */
    FIXED
}
