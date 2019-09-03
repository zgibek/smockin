package com.smockin.admin.dto;

import com.smockin.admin.persistence.enums.RestMockTypeEnum;
import com.smockin.admin.persistence.enums.RecordStatusEnum;
import com.smockin.admin.persistence.enums.RestMethodEnum;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by mgallina.
 */
public class RestfulMockDTO {

    private String path;
    private RestMethodEnum method;
    private RecordStatusEnum status;
    private RestMockTypeEnum mockType;
    private long proxyTimeoutInMillis;
    private long webSocketTimeoutInMillis;
    private long sseHeartBeatInMillis;
    private boolean proxyPushIdOnConnect;
    private boolean randomiseDefinitions;
    private boolean proxyForwardWhenNoRuleMatch;
    private boolean randomiseLatency;
    private long randomiseLatencyRangeMinMillis;
    private long randomiseLatencyRangeMaxMillis;
    private String projectId;
    private List<RestfulMockDefinitionDTO> definitions = new ArrayList<RestfulMockDefinitionDTO>();
    private List<RuleDTO> rules = new ArrayList<>();

    public RestfulMockDTO() {

    }

    public RestfulMockDTO(String path, RestMethodEnum method, RecordStatusEnum status, RestMockTypeEnum mockType, long proxyTimeoutInMillis, long webSocketTimeoutInMillis,
                          long sseHeartBeatInMillis, boolean proxyPushIdOnConnect, boolean randomiseDefinitions, boolean proxyForwardWhenNoRuleMatch,
                          boolean randomiseLatency, long randomiseLatencyRangeMinMillis, long randomiseLatencyRangeMaxMillis, String projectId) {
        this.path = path;
        this.method = method;
        this.status = status;
        this.mockType = mockType;
        this.proxyTimeoutInMillis = proxyTimeoutInMillis;
        this.webSocketTimeoutInMillis = webSocketTimeoutInMillis;
        this.sseHeartBeatInMillis = sseHeartBeatInMillis;
        this.proxyPushIdOnConnect = proxyPushIdOnConnect;
        this.randomiseDefinitions = randomiseDefinitions;
        this.proxyForwardWhenNoRuleMatch = proxyForwardWhenNoRuleMatch;
        this.randomiseLatency = randomiseLatency;
        this.randomiseLatencyRangeMinMillis = randomiseLatencyRangeMinMillis;
        this.randomiseLatencyRangeMaxMillis = randomiseLatencyRangeMaxMillis;
        this.projectId = projectId;

    }

    public String getPath() {
        return path;
    }
    public void setPath(String path) {
        this.path = path;
    }

    public RestMethodEnum getMethod() {
        return method;
    }
    public void setMethod(RestMethodEnum method) {
        this.method = method;
    }

    public RecordStatusEnum getStatus() {
        return status;
    }
    public void setStatus(RecordStatusEnum status) {
        this.status = status;
    }

    public RestMockTypeEnum getMockType() {
        return mockType;
    }
    public void setMockType(RestMockTypeEnum mockType) {
        this.mockType = mockType;
    }

    public long getProxyTimeoutInMillis() {
        return proxyTimeoutInMillis;
    }
    public void setProxyTimeoutInMillis(long proxyTimeoutInMillis) {
        this.proxyTimeoutInMillis = proxyTimeoutInMillis;
    }

    public long getWebSocketTimeoutInMillis() {
        return webSocketTimeoutInMillis;
    }
    public void setWebSocketTimeoutInMillis(long webSocketTimeoutInMillis) {
        this.webSocketTimeoutInMillis = webSocketTimeoutInMillis;
    }

    public long getSseHeartBeatInMillis() {
        return sseHeartBeatInMillis;
    }
    public void setSseHeartBeatInMillis(long sseHeartBeatInMillis) {
        this.sseHeartBeatInMillis = sseHeartBeatInMillis;
    }

    public boolean isProxyPushIdOnConnect() {
        return proxyPushIdOnConnect;
    }
    public void setProxyPushIdOnConnect(boolean proxyPushIdOnConnect) {
        this.proxyPushIdOnConnect = proxyPushIdOnConnect;
    }

    public boolean isRandomiseDefinitions() {
        return randomiseDefinitions;
    }
    public void setRandomiseDefinitions(boolean randomiseDefinitions) {
        this.randomiseDefinitions = randomiseDefinitions;
    }

    public boolean isProxyForwardWhenNoRuleMatch() {
        return proxyForwardWhenNoRuleMatch;
    }
    public void setProxyForwardWhenNoRuleMatch(boolean proxyForwardWhenNoRuleMatch) {
        this.proxyForwardWhenNoRuleMatch = proxyForwardWhenNoRuleMatch;
    }

    public boolean isRandomiseLatency() {
        return randomiseLatency;
    }
    public void setRandomiseLatency(boolean randomiseLatency) {
        this.randomiseLatency = randomiseLatency;
    }

    public long getRandomiseLatencyRangeMinMillis() {
        return randomiseLatencyRangeMinMillis;
    }
    public void setRandomiseLatencyRangeMinMillis(long randomiseLatencyRangeMinMillis) {
        this.randomiseLatencyRangeMinMillis = randomiseLatencyRangeMinMillis;
    }

    public long getRandomiseLatencyRangeMaxMillis() {
        return randomiseLatencyRangeMaxMillis;
    }
    public void setRandomiseLatencyRangeMaxMillis(long randomiseLatencyRangeMaxMillis) {
        this.randomiseLatencyRangeMaxMillis = randomiseLatencyRangeMaxMillis;
    }

    public String getProjectId() {
        return projectId;
    }
    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    public List<RestfulMockDefinitionDTO> getDefinitions() {
        return definitions;
    }
    public void setDefinitions(List<RestfulMockDefinitionDTO> definitions) {
        this.definitions = definitions;
    }

    public List<RuleDTO> getRules() {
        return rules;
    }
    public void setRules(List<RuleDTO> rules) {
        this.rules = rules;
    }

}
