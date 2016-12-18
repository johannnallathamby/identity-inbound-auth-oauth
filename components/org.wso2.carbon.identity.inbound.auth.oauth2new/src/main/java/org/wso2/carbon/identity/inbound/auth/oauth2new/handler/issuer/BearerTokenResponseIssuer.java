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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;

import java.sql.Timestamp;
import java.util.Date;
import java.util.Set;

public class BearerTokenResponseIssuer extends AccessTokenResponseIssuer {

    private static Log log = LogFactory.getLog(BearerTokenResponseIssuer.class);

    private OAuthIssuerImpl oltuIssuer = new OAuthIssuerImpl(new MD5Generator());

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return true;
    }



    protected AccessToken issueNewAccessToken(String clientId, AuthenticatedUser authzUser, String subjectIdentifier,
                                              Set<String> scopes, boolean isRefreshTokenValid,
                                              AccessToken prevAccessToken, long accessTokenCallbackValidity,
                                              long refreshTokenCallbackValidity, String grantOrResponseType,
                                              OAuth2MessageContext messageContext) {

        Timestamp timestamp = new Timestamp(new Date().getTime());

        Timestamp accessTokenIssuedTime = timestamp;

        Timestamp refreshTokenIssuedTime = timestamp;

        long accessTokenValidity = OAuth2ServerConfig.getInstance().getUserAccessTokenValidity();

        if (GrantType.CLIENT_CREDENTIALS.toString().equals(grantOrResponseType)) {
            accessTokenValidity = OAuth2ServerConfig.getInstance().getApplicationAccessTokenValidity();
        }

        if (accessTokenCallbackValidity != OAuth2.UNASSIGNED_VALIDITY_PERIOD) {
            accessTokenValidity = accessTokenCallbackValidity;
        }

        if (accessTokenValidity > 0) {
            accessTokenValidity = accessTokenValidity * 1000;
        }

        long refreshTokenValidity = OAuth2ServerConfig.getInstance().getRefreshTokenValidity();

        if (refreshTokenCallbackValidity != OAuth2.UNASSIGNED_VALIDITY_PERIOD) {
            refreshTokenValidity = refreshTokenCallbackValidity;
        }

        if(refreshTokenValidity > 0) {
            refreshTokenValidity = refreshTokenValidity * 1000;
        }

        String bearerToken;
        String refreshToken = null;
        try {
            bearerToken = oltuIssuer.accessToken();
        } catch (OAuthSystemException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
        if (isRefreshTokenValid && !OAuth2ServerConfig.getInstance().isRefreshTokenRenewalEnabled()) {
            refreshToken = prevAccessToken.getRefreshToken();
            refreshTokenIssuedTime = prevAccessToken.getRefreshTokenIssuedTime();
            refreshTokenValidity = prevAccessToken.getRefreshTokenValidity();
        } else {
            try {
                refreshToken = oltuIssuer.refreshToken();
            } catch (OAuthSystemException e) {
                throw OAuth2RuntimeException.error(e.getMessage(), e);
            }
        }

        AccessToken newAccessToken = new AccessToken(bearerToken, clientId, authzUser,
                grantOrResponseType, OAuth2.TokenState.ACTIVE, accessTokenIssuedTime, accessTokenValidity);

        newAccessToken.setScopes(scopes);
        newAccessToken.setRefreshToken(refreshToken);
        newAccessToken.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
        newAccessToken.setRefreshTokenValidity(refreshTokenValidity);

        return newAccessToken;
    }

    protected void storeNewAccessToken(AccessToken accessToken, boolean markAccessTokenExpired,
                                       boolean markAccessTokenInactive, AccessToken previousAccessToken,
                                       AuthzCode authzCode, OAuth2MessageContext messageContext) {

        HandlerManager.getInstance().getOAuth2DAO(messageContext).storeAccessToken(
                accessToken, markAccessTokenExpired, markAccessTokenInactive,
                markAccessTokenExpired || markAccessTokenInactive ? previousAccessToken.getAccessToken() : null,
                authzCode != null ? authzCode.getAuthzCode() : null, messageContext);
    }


}
