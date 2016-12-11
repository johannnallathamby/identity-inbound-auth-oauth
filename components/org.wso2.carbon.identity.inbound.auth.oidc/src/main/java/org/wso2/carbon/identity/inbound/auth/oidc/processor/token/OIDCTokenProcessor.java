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

package org.wso2.carbon.identity.inbound.auth.oidc.processor.token;


import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.TokenRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.token.TokenResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2.ClientType;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.token.TokenProcessor;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.token.OIDCTokenResponse;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCache;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheAccessTokenKey;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheCodeKey;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheEntry;
import org.wso2.carbon.identity.inbound.auth.oidc.handler.OIDCHandlerManager;

import java.util.HashMap;

/*
 * InboundRequestProcessor for OAuth2 Token Endpoint
 */
public class OIDCTokenProcessor extends TokenProcessor {

    private static final Log log = LogFactory.getLog(OIDCTokenProcessor.class);

    @Override
    public String getName() {
        return "OIDCTokenProcessor";
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if(identityRequest.getParameter(OAuth.OAUTH_GRANT_TYPE) != null) {
            return true;
        }
        return false;
    }

    @Override
    public TokenResponse.TokenResponseBuilder process(IdentityRequest identityRequest)
            throws FrameworkException {

        OAuth2TokenMessageContext messageContext = new OAuth2TokenMessageContext(
                (TokenRequest) identityRequest, new HashMap<String,String>());

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            String clientId = authenticateClient(messageContext);
            messageContext.setClientId(clientId);
        }

        validateGrant(messageContext);

        AccessToken accessToken = issueAccessToken(messageContext);

        // Here we are replacing the AuthenticationResultCacheEntry with AccessTokenKey to be able to read it from
        // Userinfo endpoint.
        // The day we can invoke Authentication Framework via Java APIs, we can get rid of this hack
        AuthzCode authzCode = (AuthzCode) messageContext.getParameter(OAuth2.AUTHZ_CODE);
        if (authzCode != null) {
            replaceEntryWithAccessToken(authzCode.getAuthzCodeId(), authzCode.getAuthzCode(),
                                        accessToken.getAccessTokenId(), accessToken.getAccessToken());
        } else {
            // need to think how to generate Userinfo response for password grant type
        }

        return buildTokenResponse(accessToken, messageContext);

    }

    /**
     * Finds out the client type
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected ClientType clientType(OAuth2TokenMessageContext messageContext) {
        return HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected String authenticateClient(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        return HandlerManager.getInstance().authenticateClient(messageContext);
    }

    /**
     * Validates the Authorization Grant
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the authorization grant is valid
     * @throws OAuth2ClientException, OAuth2Exception
     */
    protected void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {
        HandlerManager.getInstance().validateGrant(messageContext);
    }

    protected TokenResponse.TokenResponseBuilder buildTokenResponse(AccessToken accessToken,
                                                                    OAuth2TokenMessageContext messageContext) {

        TokenResponse.TokenResponseBuilder oauth2Builder = super.buildTokenResponse(accessToken, messageContext);

        OIDCTokenResponse.OIDCTokenResponseBuilder oidcBuilder = new OIDCTokenResponse.OIDCTokenResponseBuilder
                (oauth2Builder, messageContext);

        if(accessToken.getScopes().contains(OIDC.OPENID_SCOPE)){
            addIDToken(oidcBuilder, messageContext);
        }

        return oauth2Builder;
    }

    protected void addIDToken(OIDCTokenResponse.OIDCTokenResponseBuilder builder, OAuth2TokenMessageContext messageContext) {

        IDTokenClaimsSet idTokenClaimsSet = OIDCHandlerManager.getInstance().buildIDToken(messageContext);
        builder.setIdTokenClaimsSet(idTokenClaimsSet);
    }

    /**
     * Issues the access token
     *
     * @param messageContext The runtime message context
     * @return OAuth2 access token response
     */
    protected AccessToken issueAccessToken(OAuth2TokenMessageContext messageContext) {

        AccessToken accessToken = HandlerManager.getInstance().issueAccessToken(messageContext);
        messageContext.addParameter(OIDC.ACCESS_TOKEN, accessToken);
        return accessToken;
    }

    protected void replaceEntryWithAccessToken(String codeId, String code, String accessTokenId, String accessToken) {

        OIDCCacheCodeKey codeKey = new OIDCCacheCodeKey(codeId, code);
        OIDCCacheEntry entry = OIDCCache.getInstance().getValueFromCache(codeKey);
        if(entry == null) {
            log.fatal("AuthzCode entry could not be found for codeId: " + codeId +". Couldn't replace AuthnResult " +
                      "against new access token: " + accessTokenId);
            return;
        }

        OIDCCacheAccessTokenKey tokenKey = new OIDCCacheAccessTokenKey(accessTokenId, accessToken);
        OIDCCache.getInstance().addToCache(tokenKey, entry);
    }
}
