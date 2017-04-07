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

package org.wso2.carbon.identity.inbound.auth.oauth2new.handler.issuer;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.refresh.RefreshGrantRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Utils;

import java.util.HashSet;
import java.util.Set;

/*
 * To generate OAuth2 access tokens
 */
public abstract class AccessTokenResponseIssuer extends AbstractIdentityMessageHandler {

    private static Log log = LogFactory.getLog(AccessTokenResponseIssuer.class);

    protected static final String IS_ACCESS_TOKEN_VALID = "IsAccessTokenValid";
    protected static final String IS_REFRESH_TOKEN_VALID = "IsRefreshTokenValid";
    protected static final String MARK_ACCESS_TOKEN_EXPIRED = "MarkAccessTokenExpired";
    protected static final String MARK_ACCESS_TOKEN_INACTIVE = "MarkAccessTokenInactive";

    // TODO: move this implementation to framework, remove it from here and update framework dependency version
    public String getName() {
        return this.getClass().getSimpleName();
    }

    /**
     * Issues the access token response.
     *
     * @param messageContext The runtime message context
     * @return Returns the OAuth2 response
     * @throws OAuth2Exception
     */
    public AccessToken issue(OAuth2MessageContext messageContext) {

        HandlerManager.getInstance().triggerPreTokenIssuers(messageContext);

        AccessToken accessToken = validTokenExists(messageContext);
        boolean isAccessTokenValid = (Boolean)messageContext.getParameter(IS_ACCESS_TOKEN_VALID);
        boolean isRefreshTokenValid = (Boolean)messageContext.getParameter(IS_REFRESH_TOKEN_VALID);
        if(!isAccessTokenValid || !isRefreshTokenValid || messageContext.getRequest() instanceof RefreshGrantRequest) {
            accessToken = issueNewAccessToken(messageContext);
            AuthzCode authzCode = (AuthzCode)messageContext.getParameter(OAuth2.AUTHZ_CODE);
            boolean markAccessTokenExpired = BooleanUtils.isTrue((Boolean) messageContext.getParameter
                    (MARK_ACCESS_TOKEN_EXPIRED));
            boolean markAccessTokenInactive = BooleanUtils.isTrue((Boolean) messageContext.getParameter(
                    MARK_ACCESS_TOKEN_INACTIVE));
            AccessToken previousAccessToken = (AccessToken) messageContext.getParameter(OAuth2.PREV_ACCESS_TOKEN);
            storeNewAccessToken(accessToken, markAccessTokenExpired, markAccessTokenInactive, previousAccessToken,
                                authzCode, messageContext);
        }

        HandlerManager.getInstance().triggerPostTokenIssuers(messageContext);

        return accessToken;
    }

    protected AccessToken validTokenExists(OAuth2MessageContext messageContext) {

        if(messageContext instanceof AuthzMessageContext) {
            return validTokenExists((AuthzMessageContext)messageContext);
        } else if (messageContext instanceof TokenMessageContext) {
            return validTokenExists((TokenMessageContext)messageContext);
        } else {
            throw OAuth2RuntimeException.error("");
        }
    }

    protected AccessToken validTokenExists(AuthzMessageContext messageContext) {

        String clientId = messageContext.getApplication().getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        return validTokenExists(clientId, authzUser, scopes, messageContext);
    }

    protected AccessToken validTokenExists(TokenMessageContext messageContext) {

        String clientId = messageContext.getApplication().getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        return validTokenExists(clientId, authzUser, scopes, messageContext);
    }

    protected AccessToken validTokenExists(String clientId, AuthenticatedUser authzUser,
                                           Set<String> scopes, OAuth2MessageContext messageContext) {

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        // for refresh_token grant
        AccessToken accessToken = (AccessToken) messageContext.getParameter(OAuth2.PREV_ACCESS_TOKEN);
        if(accessToken == null) {
            Set<String> activeExpiredToken = new HashSet();
            activeExpiredToken.add(OAuth2.TokenState.ACTIVE);
            activeExpiredToken.add(OAuth2.TokenState.EXPIRED);
            accessToken = dao.getLatestAccessToken(clientId, authzUser, scopes, activeExpiredToken, messageContext);
        }
        boolean isAccessTokenValid = false;
        boolean isRefreshTokenValid = false;
        boolean markAccessTokenExpired = false;

        if (accessToken != null) {
            if (OAuth2.TokenState.ACTIVE.equals(accessToken.getAccessTokenState())) {
                long expireTime = OAuth2Utils.getTokenValidityPeriod(accessToken);
                if (expireTime > 0 || expireTime < 0) {
                    if (log.isDebugEnabled()) {
                        if (expireTime > 0) {
                            if(log.isDebugEnabled()) {
                                log.debug("ACTIVE access token found for " + OAuth2Utils.createUniqueAuthzGrantString
                                        (authzUser, clientId, scopes));
                            }
                        } else if (expireTime < 0) {
                            if (log.isDebugEnabled()) {
                                log.debug("Infinite lifetime access token found for " + OAuth2Utils
                                        .createUniqueAuthzGrantString(authzUser, clientId, scopes));
                            }
                        }
                    }
                    isAccessTokenValid = true;
                    long refreshTokenExpiryTime = OAuth2Utils.getRefreshTokenValidityPeriod(accessToken);
                    if (refreshTokenExpiryTime < 0 || refreshTokenExpiryTime > 0) {
                        if (log.isDebugEnabled()) {
                            if (refreshTokenExpiryTime < 0) {
                                if(log.isDebugEnabled()) {
                                    log.debug("Infinite lifetime refresh token found for " + OAuth2Utils
                                            .createUniqueAuthzGrantString(authzUser, clientId, scopes));
                                }
                            } else if (refreshTokenExpiryTime > 0) {
                                if(log.isDebugEnabled()) {
                                    log.debug("ACTIVE refresh token found for " + OAuth2Utils.createUniqueAuthzGrantString
                                            (authzUser, clientId, scopes));
                                }
                            }
                        }
                        isRefreshTokenValid = true;
                    }
                } else {
                    markAccessTokenExpired = true;
                }
            } else {
                long refreshTokenExpiryTime = OAuth2Utils.getRefreshTokenValidityPeriod(accessToken);
                if (refreshTokenExpiryTime < 0 || refreshTokenExpiryTime > 0) {
                    if (log.isDebugEnabled()) {
                        if (refreshTokenExpiryTime < 0) {
                            if(log.isDebugEnabled()) {
                                log.debug("Infinite lifetime refresh token found for " + OAuth2Utils
                                        .createUniqueAuthzGrantString(authzUser, clientId, scopes));
                            }
                        } else if (refreshTokenExpiryTime > 0) {
                            if(log.isDebugEnabled()) {
                                log.debug("ACTIVE refresh token found for " + OAuth2Utils.createUniqueAuthzGrantString
                                        (authzUser, clientId, scopes));
                            }
                        }
                    }
                    isRefreshTokenValid = true;
                }
            }

        }
        messageContext.addParameter(IS_ACCESS_TOKEN_VALID, isAccessTokenValid);
        messageContext.addParameter(IS_REFRESH_TOKEN_VALID, isRefreshTokenValid);
        if(messageContext.getRequest() instanceof RefreshGrantRequest) {
            messageContext.addParameter(MARK_ACCESS_TOKEN_INACTIVE, true);
        } else {
            messageContext.addParameter(MARK_ACCESS_TOKEN_EXPIRED, markAccessTokenExpired);
        }
        if(messageContext.getParameter(OAuth2.PREV_ACCESS_TOKEN) == null) {
            messageContext.addParameter(OAuth2.PREV_ACCESS_TOKEN, accessToken);
        }
        return accessToken;
    }

    protected AccessToken issueNewAccessToken(OAuth2MessageContext messageContext) {

        if(messageContext instanceof AuthzMessageContext) {
            return issueNewAccessToken((AuthzMessageContext) messageContext);
        } else if (messageContext instanceof TokenMessageContext) {
            return issueNewAccessToken((TokenMessageContext) messageContext);
        } else {
            throw OAuth2RuntimeException.error("");
        }
    }

    protected AccessToken issueNewAccessToken(AuthzMessageContext messageContext) {

        boolean isRefreshTokenValid = (Boolean)messageContext.getParameter(IS_REFRESH_TOKEN_VALID);
        AccessToken prevAccessToken = (AccessToken)messageContext.getParameter(OAuth2.PREV_ACCESS_TOKEN);
        String clientId = messageContext.getRequest().getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        long accessTokenCallbackValidity = messageContext.getAccessTokenValidityPeriod();
        long refreshTokenCallbackValidity = messageContext.getRefreshTokenValidityPeriod();
        String responseType = messageContext.getRequest().getResponseType();
        return issueNewAccessToken(clientId, authzUser, authzUser.getAuthenticatedSubjectIdentifier(), scopes,
                                   isRefreshTokenValid, prevAccessToken, accessTokenCallbackValidity,
                                   refreshTokenCallbackValidity, responseType, messageContext);
    }

    protected AccessToken issueNewAccessToken(TokenMessageContext messageContext) {

        boolean isRefreshTokenValid = (Boolean)messageContext.getParameter(IS_REFRESH_TOKEN_VALID);
        AccessToken prevAccessToken = (AccessToken)messageContext.getParameter(OAuth2.PREV_ACCESS_TOKEN);
        String clientId = messageContext.getApplication().getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        long accessTokenValidityPeriod = messageContext.getAccessTokenValidityPeriod();
        long refreshTokenValidityPeriod = messageContext.getRefreshTokenValidityPeriod();
        String grantType = messageContext.getRequest().getGrantType();
        return issueNewAccessToken(clientId, authzUser, authzUser.getAuthenticatedSubjectIdentifier(), scopes,
                                   isRefreshTokenValid, prevAccessToken, accessTokenValidityPeriod,
                                   refreshTokenValidityPeriod, grantType, messageContext);
    }

    protected abstract AccessToken issueNewAccessToken(String clientId, AuthenticatedUser authzUser,
                                                       String subjectIdentifier, Set<String> scopes,
                                                       boolean isRefreshTokenValid, AccessToken prevAccessToken,
                                                       long accessTokenCallbackValidity,
                                                       long refreshTokenCallbackValidity, String grantOrResponseType,
                                                       OAuth2MessageContext messageContext);

    protected abstract void storeNewAccessToken(AccessToken accessToken, boolean markAccessTokenExpired,
                                                boolean markAccessTokenInactive, AccessToken previousAccessToken,
                                                AuthzCode authzCode, OAuth2MessageContext messageContext);

}
