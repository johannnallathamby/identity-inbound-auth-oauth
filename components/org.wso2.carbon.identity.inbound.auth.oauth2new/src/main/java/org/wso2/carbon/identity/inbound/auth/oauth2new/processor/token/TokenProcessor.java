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

package org.wso2.carbon.identity.inbound.auth.oauth2new.processor.token;


import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2.ClientType;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.TokenRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.token.TokenResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.OAuth2IdentityRequestProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/*
 * InboundRequestProcessor for OAuth2 Token Endpoint
 */
public class TokenProcessor extends OAuth2IdentityRequestProcessor {

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        return identityRequest instanceof TokenRequest;
    }

    @Override
    public TokenResponse.TokenResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        TokenMessageContext messageContext = new TokenMessageContext(
                (TokenRequest) identityRequest, new HashMap<String,String>());

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            authenticateClient(messageContext);
        }

        validateGrant(messageContext);

        AccessToken accessToken = issueAccessToken(messageContext);

        return buildTokenResponse(accessToken, messageContext);

    }

    /**
     * Finds out the client type
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected ClientType clientType(TokenMessageContext messageContext) {
        return HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2ClientException
     */
    protected void authenticateClient(TokenMessageContext messageContext) throws OAuth2ClientException {
        HandlerManager.getInstance().authenticateClient(messageContext);
    }

    /**
     * Validates the Authorization Grant
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the authorization grant is valid
     * @throws OAuth2Exception
     */
    protected void validateGrant(TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {
        HandlerManager.getInstance().validateGrant(messageContext);
    }

    protected TokenResponse.TokenResponseBuilder buildTokenResponse(AccessToken accessToken,
                                                                        TokenMessageContext messageContext) {

        long expiry = 0;
        if(accessToken.getAccessTokenValidity() > 0) {
            expiry = accessToken.getAccessTokenValidity()/1000;
        } else {
            expiry = Long.MAX_VALUE/1000;
        }

        String refreshToken = null;
        if(messageContext.getApplication().getGrantTypes().contains(GrantType.REFRESH_TOKEN.toString())) {
            if(issueRefreshToken(messageContext)) {
                refreshToken = accessToken.getRefreshToken();
            }
        }

        OAuthASResponse.OAuthTokenResponseBuilder oltuRespBuilder = OAuthASResponse
                .tokenResponse(HttpServletResponse.SC_OK)
                .setAccessToken(accessToken.getAccessToken())
                .setExpiresIn(Long.toString(expiry))
                .setTokenType(OAuth.OAUTH_HEADER_NAME);
        if(refreshToken != null) {
            oltuRespBuilder.setRefreshToken(new String(refreshToken));
        }
        oltuRespBuilder.setScope(OAuth2Util.buildScopeString(accessToken.getScopes()));

        TokenResponse.TokenResponseBuilder builder = new TokenResponse.TokenResponseBuilder(messageContext);
        builder.setBuilder(oltuRespBuilder);
        return builder;
    }

    /**
     * Issues the access token
     *
     * @param messageContext The runtime message context
     * @return OAuth2 access token response
     * @throws OAuth2Exception
     */
    protected AccessToken issueAccessToken(TokenMessageContext messageContext) {
        AccessToken accessToken = HandlerManager.getInstance().issueAccessToken(messageContext);
        messageContext.addParameter(OAuth2.ACCESS_TOKEN, accessToken);
        return accessToken;
    }
}
