/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.inbound.auth.oauth2new.analytics;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.authzcode.AuthzCodeGrantRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.clientcredentials.ClientCredentialsGrantRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.password.PasswordGrantRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.refresh.RefreshGrantRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.interceptor.OAuth2EventInterceptor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.internal.OAuth2DataHolder;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RORevocationMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.HashSet;
import java.util.Set;

public class DASDataPublisher extends OAuth2EventInterceptor {

    private static Log log = LogFactory.getLog(DASDataPublisher.class);

    public void onPostTokenIssue(OAuth2MessageContext messageContext) {

        AccessToken accessToken = (AccessToken) messageContext.getParameter(OAuth2.ACCESS_TOKEN);
        TokenData tokenData = new TokenData();
        tokenData.setUser(accessToken.getAuthzUser().getUserName());
        tokenData.setUserStoreDomain(accessToken.getAuthzUser().getUserStoreDomain());
        tokenData.setTenantDomain(accessToken.getAuthzUser().getTenantDomain());
        tokenData.setIsSuccess(true);
        tokenData.setTokenId(accessToken.getAccessTokenId());
        tokenData.setGrantType(accessToken.getGrantType());
        tokenData.setClientId(accessToken.getClientId());
        tokenData.setAccessTokenValidityMillis(accessToken.getAccessTokenValidity());
        tokenData.setRefreshTokenValidityMillis(accessToken.getRefreshTokenValidity());
        tokenData.setIssuedTime(accessToken.getAccessTokenIssuedTime().getTime());
        tokenData.setAuthzScopes(OAuth2Util.buildScopeString(accessToken.getScopes()));
        String[] publishingTenantDomains = DataPublisherUtils.getTenantDomains(
                messageContext.getRequest().getTenantDomain(), accessToken.getAuthzUser().getTenantDomain());
        tokenData.addParameter(DataPublisherConstants.TENANT_ID, publishingTenantDomains);
        if(messageContext instanceof AuthzMessageContext) {
            Set<String> approvedScopes = accessToken.getScopes();
            Set<String> requestedScopes = ((AuthzMessageContext)messageContext).getRequest().getScopes();
            Set<String> unauthzScopes = new HashSet(requestedScopes);
            unauthzScopes.removeAll(approvedScopes);
            tokenData.setUnAuthzScopes(OAuth2Util.buildScopeString(unauthzScopes));
        } else if(messageContext instanceof TokenMessageContext) {
            Set<String> approvedScopes = accessToken.getScopes();
            Set<String> requestedScopes = null;
            if(messageContext.getRequest() instanceof AuthzCodeGrantRequest) {
                requestedScopes = null;
            } else if(messageContext.getRequest() instanceof PasswordGrantRequest) {
                requestedScopes = ((PasswordGrantRequest) messageContext.getRequest()).getScopes();
            } else if(messageContext.getRequest() instanceof ClientCredentialsGrantRequest) {
                requestedScopes = ((ClientCredentialsGrantRequest) messageContext.getRequest()).getScopes();
            } else if(messageContext.getRequest() instanceof RefreshGrantRequest) {
                requestedScopes = ((RefreshGrantRequest) messageContext.getRequest()).getScopes();
            } else if(messageContext.getParameter(OAuth2.REQUESTED_SCOPES) != null) {
                requestedScopes = (Set<String>)messageContext.getParameter(OAuth2.REQUESTED_SCOPES);
            }
            Set<String> unauthzScopes = new HashSet(requestedScopes);
            unauthzScopes.removeAll(approvedScopes);
            tokenData.setUnAuthzScopes(OAuth2Util.buildScopeString(unauthzScopes));
        }
        this.publishTokenIssueEvent(tokenData);
    }

    public void onPostTokenRevocationByClient(RevocationMessageContext messageContext) {

        AccessToken accessToken = (AccessToken) messageContext.getParameter(OAuth2.ACCESS_TOKEN);
        if(accessToken != null) {
            TokenData tokenData = new TokenData();
            tokenData.setIsSuccess(true);
            tokenData.setTokenId(accessToken.getAccessTokenId());
            tokenData.setClientId(accessToken.getClientId());
            tokenData.setUser(accessToken.getAuthzUser().getUserName());
            tokenData.setTenantDomain(accessToken.getAuthzUser().getTenantDomain());
            tokenData.setUserStoreDomain(accessToken.getAuthzUser().getUserStoreDomain());
            tokenData.setIssuedTime(accessToken.getAccessTokenIssuedTime().getTime());
            tokenData.setGrantType(accessToken.getGrantType());
            tokenData.setAuthzScopes(OAuth2Util.buildScopeString(accessToken.getScopes()));
            String spTenantDomain = null;
            // get SP tenant domain from application.mgt service
            tokenData.setRevokedTime(System.currentTimeMillis());
            tokenData.addParameter(DataPublisherConstants.TENANT_ID, DataPublisherUtils.getTenantDomains
                    (spTenantDomain, tokenData.getTenantDomain()));
            doPublishRevocationByResourceOwner(tokenData);
        }
    }

    public void onPostTokenRevocationByResourceOwner(AuthenticatedUser user, RORevocationMessageContext messageContext)  {

        Set<AccessToken> accessTokens = (Set<AccessToken>)messageContext.getParameter(OAuth2.REVOKED_ACCESS_TOKENS);
        if(accessTokens != null) {
            for (AccessToken accessToken : accessTokens) {
                publishRevocationByResourceOwner(accessToken, messageContext);
            }
        }
    }

    public void onPostTokenRevocationByResourceOwner(AuthenticatedUser user, String clientId,
                                                     RORevocationMessageContext messageContext)  {

        AccessToken accessToken = (AccessToken)messageContext.getParameter(OAuth2.ACCESS_TOKEN);
        if(accessToken != null) {
            publishRevocationByResourceOwner(accessToken, messageContext);
        }

    }

    protected void publishRevocationByResourceOwner(AccessToken accessToken, RORevocationMessageContext
            messageContext) {

        TokenData tokenData = new TokenData();
        // get SP tenant domain from application.mgt service
        String spTenantDomain = null;
        tokenData.setIsSuccess(true);
        tokenData.setClientId(accessToken.getClientId());
        tokenData.setTokenId(accessToken.getAccessTokenId());
        tokenData.setGrantType(accessToken.getGrantType());
        tokenData.setAuthzScopes(OAuth2Util.buildScopeString(accessToken.getScopes()));
        tokenData.setIssuedTime(accessToken.getAccessTokenIssuedTime().getTime());
        tokenData.setUser(accessToken.getAuthzUser().getUserName());
        tokenData.setTenantDomain(accessToken.getAuthzUser().getTenantDomain());
        tokenData.setUserStoreDomain(accessToken.getAuthzUser().getUserStoreDomain());
        tokenData.setRevokedTime(System.currentTimeMillis());
        tokenData.addParameter(DataPublisherConstants.TENANT_ID, DataPublisherUtils.getTenantDomains
                (spTenantDomain, tokenData.getTenantDomain()));
        doPublishRevocationByResourceOwner(tokenData);
    }

    public void onPostTokenIntrospection(IntrospectionMessageContext messageContext) {

        AccessToken accessToken = (AccessToken) messageContext.getParameter(OAuth2.ACCESS_TOKEN);
        if(accessToken != null) {
            TokenData tokenData = new TokenData();
            tokenData.setTokenId(accessToken.getAccessTokenId());
            tokenData.setUser(accessToken.getAuthzUser().getUserName());
            tokenData.setTenantDomain(accessToken.getAuthzUser().getTenantDomain());
            tokenData.setUserStoreDomain(accessToken.getAuthzUser().getUserStoreDomain());
            tokenData.setGrantType(accessToken.getGrantType());
            tokenData.setClientId(accessToken.getClientId());
            // get SP tenant domain from application.mgt service
            String spTenantDomain = null;
            String[] publishingTenantDomains = DataPublisherUtils.getTenantDomains(spTenantDomain,
                                                                                   accessToken.getAuthzUser()
                                                                                                .getTenantDomain());
            tokenData.addParameter(DataPublisherConstants.TENANT_ID, publishingTenantDomains);
            tokenData.setAuthzScopes(OAuth2Util.buildScopeString(accessToken.getScopes()));
            tokenData.setIssuedTime(accessToken.getAccessTokenIssuedTime().getTime());
            tokenData.setAccessTokenValidityMillis(accessToken.getAccessTokenValidity());
            boolean isActive = !OAuth2.TokenState.ACTIVE.equals(accessToken.getAccessTokenState()) && OAuth2Util
                                                                                                              .getAccessTokenValidityPeriod(accessToken) == 0 ? false : true;
            tokenData.setIsActive(isActive);
            if (isActive && OAuth2Util.getAccessTokenValidityPeriod(accessToken) > 0) {
                tokenData.setAccessTokenValidityMillis(OAuth2Util.getAccessTokenValidityPeriod(accessToken));
            }
            doPublishOauthTokenValidation(tokenData);
        }
    }

    protected void publishTokenIssueEvent(TokenData tokenData) {

        Object[] payloadData = new Object[14];
        payloadData[0] = tokenData.getUser();
        payloadData[1] = tokenData.getTenantDomain();
        payloadData[2] = tokenData.getUserStoreDomain();
        payloadData[3] = tokenData.getClientId();
        payloadData[4] = tokenData.getGrantType();
        payloadData[5] = tokenData.getTokenId();
        payloadData[6] = tokenData.getAuthzScopes();
        payloadData[7] = tokenData.getUnAuthzScopes();
        payloadData[8] = tokenData.isSuccess();
        payloadData[9] = tokenData.getErrorCode();
        payloadData[10] = tokenData.getErrorMsg();
        payloadData[11] = tokenData.getAccessTokenValidityMillis();
        payloadData[12] = tokenData.getRefreshTokenValidityMillis();
        payloadData[13] = tokenData.getIssuedTime();

        String[] publishingDomains = (String[]) tokenData.getParameter(DataPublisherConstants.TENANT_ID);
        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = DataPublisherUtils.getMetaDataArray(publishingDomain);
                    Event event = new Event(DataPublisherConstants.TOKEN_ISSUE_EVENT_STREAM_NAME, System
                            .currentTimeMillis(), metadataArray, null, payloadData);
                    OAuth2DataHolder.getInstance().getEventStreamService().publish(event);
                    if (log.isDebugEnabled() && event != null) {
                        log.debug("Sending out event : " + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    protected void doPublishOauthTokenValidation(TokenData tokenData) {

        Object[] payloadData = new Object[10];

        payloadData[0] = tokenData.getTokenId();
        payloadData[1] = tokenData.getClientId();
        payloadData[2] = tokenData.getUser();
        payloadData[3] = tokenData.getTenantDomain();
        payloadData[4] = tokenData.getUserStoreDomain();
        payloadData[5] = tokenData.getGrantType();
        payloadData[6] = tokenData.getAuthzScopes();
        payloadData[7] = tokenData.isActive();
        payloadData[8] = tokenData.getAccessTokenValidityMillis();
        payloadData[9] = tokenData.getIssuedTime();

        String[] publishingDomains = (String[]) tokenData.getParameter(DataPublisherConstants.TENANT_ID);
        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = DataPublisherUtils.getMetaDataArray(publishingDomain);
                    Event event = new Event(DataPublisherConstants.TOKEN_VALIDATION_EVENT_STREAM_NAME, System
                            .currentTimeMillis(), metadataArray, null, payloadData);
                    OAuth2DataHolder.getInstance().getEventStreamService().publish(event);
                    if (log.isDebugEnabled() && event != null) {
                        log.debug("Sending out event : " + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    protected void doPublishRevocationByResourceOwner(TokenData tokenData) {

        Object[] payloadData = new Object[12];

        payloadData[0] = tokenData.getTokenId();
        payloadData[1] = tokenData.getClientId();
        payloadData[2] = tokenData.getUser();
        payloadData[3] = tokenData.getTenantDomain();
        payloadData[4] = tokenData.getUserStoreDomain();
        payloadData[5] = tokenData.getGrantType();
        payloadData[6] = tokenData.getAuthzScopes();
        payloadData[7] = tokenData.getRevokedTime();
        payloadData[8] = tokenData.getIssuedTime();
        payloadData[9] = tokenData.isSuccess();
        payloadData[10] = tokenData.getErrorMsg();
        payloadData[11] = tokenData.getErrorCode();

        String[] publishingDomains = (String[]) tokenData.getParameter(DataPublisherConstants.TENANT_ID);
        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = DataPublisherUtils.getMetaDataArray(publishingDomain);
                    Event event = new Event(DataPublisherConstants.TOKEN_REVOKE_EVENT_STREAM_NAME, System
                            .currentTimeMillis(), metadataArray, null, payloadData);
                    OAuth2DataHolder.getInstance().getEventStreamService().publish(event);
                    if (log.isDebugEnabled() && event != null) {
                        log.debug("Sending out event : " + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }
}
