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

package org.wso2.carbon.identity.inbound.auth.oauth2new.introspect;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

public class IntrospectionHandler extends AbstractIdentityMessageHandler {

    // TODO: move this implementation to framework, remove it from here and update framework dependency version
    public String getName() {
        return this.getClass().getSimpleName();
    }

    public IntrospectionResponse.IntrospectionResponseBuilder introspect(IntrospectionMessageContext messageContext)
            throws OAuth2ClientException {

        IntrospectionRequest introspectionRequest = (IntrospectionRequest)messageContext.getRequest();
        String token = introspectionRequest.getToken();
        String tokenTypeHint = introspectionRequest.getTokenTypeHint();
        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        boolean refreshTokenFirst = GrantType.REFRESH_TOKEN.toString().equals(tokenTypeHint) ? true : false;
        boolean isRefreshToken = false;
        AccessToken accessToken = null;
        if (refreshTokenFirst) {
            accessToken = dao.getLatestAccessTokenByRefreshToken(token, messageContext);
            isRefreshToken = true;
            if(accessToken == null) {
                accessToken = dao.getAccessToken(token, messageContext);
            }
        } else {
            accessToken = dao.getAccessToken(token, messageContext);
            if (accessToken == null) {
                accessToken = dao.getLatestAccessTokenByRefreshToken(token, messageContext);
                isRefreshToken = true;
            }
        }

        if(accessToken != null) {
            messageContext.addParameter(OAuth2.ACCESS_TOKEN, accessToken);
            if(isRefreshToken) {
                return introspectRefreshToken(accessToken, messageContext);
            } else {
                return introspectAccessToken(accessToken, messageContext);
            }
        } else {
            throw OAuth2ClientException.error("Invalid token");
        }
    }

    public IntrospectionResponse.IntrospectionResponseBuilder introspectAccessToken(AccessToken accessToken,
                                                                                    IntrospectionMessageContext messageContext) {

        IntrospectionResponse.IntrospectionResponseBuilder builder = new IntrospectionResponse
                .IntrospectionResponseBuilder(messageContext);

        builder.setTokenType(OAuth.OAUTH_ACCESS_TOKEN);
        builder.setExp((accessToken.getAccessTokenIssuedTime().getTime() + accessToken.getAccessTokenValidity())
                       / 1000);
        builder.setIat(accessToken.getAccessTokenIssuedTime().getTime()/1000);
        builder.setNbf(accessToken.getAccessTokenIssuedTime().getTime()/1000);
        builder.setJti(accessToken.getAccessToken());
        return builder;
    }

    public IntrospectionResponse.IntrospectionResponseBuilder introspectRefreshToken(AccessToken accessToken,
                                                                                     IntrospectionMessageContext messageContext) {

        IntrospectionResponse.IntrospectionResponseBuilder builder = new IntrospectionResponse
                .IntrospectionResponseBuilder(messageContext);

        builder.setTokenType(OAuth.OAUTH_REFRESH_TOKEN);
        builder.setExp((accessToken.getRefreshTokenIssuedTime().getTime() + accessToken.getRefreshTokenValidity())
                       / 1000);
        builder.setIat(accessToken.getRefreshTokenIssuedTime().getTime()/1000);
        builder.setNbf(accessToken.getRefreshTokenIssuedTime().getTime()/1000);
        builder.setJti(accessToken.getRefreshToken());
        return builder;
    }

    protected IntrospectionResponse.IntrospectionResponseBuilder introspectToken(
            AccessToken accessToken, IntrospectionMessageContext messageContext,
            IntrospectionResponse.IntrospectionResponseBuilder builder) {

        if(!OAuth2.TokenState.ACTIVE.equals(accessToken.getAccessTokenState())) {
            // json string should not contain other attributes, only active=false
            builder.setActive(false);
            return builder;
        } else if (OAuth2Util.getAccessTokenValidityPeriod(accessToken) == 0) {
            // json string should not contain other attributes, only active=false
            builder.setActive(false);
            return builder;
        } else {
            builder.setActive(true);
            builder.setScope(OAuth2Util.buildScopeString(accessToken.getScopes()));
            builder.setClientId(accessToken.getClientId());
            OAuth2App app = messageContext.getApplication();
            if(!accessToken.getAuthzUser().isFederatedUser()) {
                boolean useTenantDomain = app.isUseTenantDomainInLocalSubjectIdentifier();
                boolean useUserstoreDomain = app.isUseUserstoreDomainInLocalSubjectIdentifier();
                builder.setUsername(accessToken.getAuthzUser().getUsernameAsSubjectIdentifier(useUserstoreDomain,
                                                                                              useTenantDomain));
            } else {
                builder.setUsername(accessToken.getAuthzUser().getAuthenticatedSubjectIdentifier());
            }
            builder.setAud(accessToken.getClientId());
            if(ResponseType.TOKEN.toString().equals(accessToken.getGrantType())) {
                builder.setIss(OAuth2ServerConfig.getInstance().getOAuth2AuthzEPUrl());
            } else {
                builder.setIss(OAuth2ServerConfig.getInstance().getOAuth2TokenEPUrl());
            }
            return builder;
        }
    }
}
