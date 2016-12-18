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
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.token.TokenProcessor;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.token.OIDCTokenResponse;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCache;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheAccessTokenKey;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheCodeKey;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheEntry;
import org.wso2.carbon.identity.inbound.auth.oidc.handler.HandlerManager;

import java.util.HashMap;

/*
 * IdentityProcessor for OIDC Token Endpoint
 */
public class OIDCTokenProcessor extends TokenProcessor {

    private static final Log log = LogFactory.getLog(OIDCTokenProcessor.class);

    public int getPriority() {
        return 2;
    }

    // need to think about this logic. how to differentiate between oauth2 and oidc token requests
    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if(super.canHandle(identityRequest)) {
            return true;
        }
        return false;
    }

    @Override
    public TokenResponse.TokenResponseBuilder process(IdentityRequest identityRequest)
            throws FrameworkException {

        TokenMessageContext messageContext = new TokenMessageContext(
                (TokenRequest) identityRequest, new HashMap<String,String>());

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            authenticateClient(messageContext);
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
            //TODO: need to think how to generate Userinfo response for password grant type
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
    protected ClientType clientType(TokenMessageContext messageContext) {
        return org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @throws OAuth2ClientException if the client was not authenticated successfully
     */
    protected void authenticateClient(TokenMessageContext messageContext) throws OAuth2ClientException {
        org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager.getInstance().authenticateClient(messageContext);
    }

    /**
     * Validates the Authorization Grant
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the authorization grant is valid
     * @throws OAuth2ClientException, OAuth2Exception
     */
    protected void validateGrant(TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {
        org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager.getInstance().validateGrant(messageContext);
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

    protected TokenResponse.TokenResponseBuilder buildTokenResponse(AccessToken accessToken,
                                                                    TokenMessageContext messageContext) {

        TokenResponse.TokenResponseBuilder oauth2Builder = super.buildTokenResponse(accessToken, messageContext);

        OIDCTokenResponse.OIDCTokenResponseBuilder oidcBuilder =
                new OIDCTokenResponse.OIDCTokenResponseBuilder(messageContext);
        oidcBuilder.setOLTUBuilder(oauth2Builder.getBuilder());

        // TODO: need to verify this. We are assuming only for "response_type=code" and "grant_type=password" id_token
        // TODO: is issued from token endpoint. This may fail when we start supporting other response types like
        // TODO: "code id_token" or "code token"
        if(messageContext.getParameter(OAuth2.AUTHZ_CODE) != null || GrantType.PASSWORD.toString().equals(
                messageContext.getRequest().getGrantType())) {
            addIDToken(oidcBuilder, messageContext);
        }

        return oidcBuilder;
    }

    protected void addIDToken(OIDCTokenResponse.OIDCTokenResponseBuilder builder, TokenMessageContext messageContext) {

        IDTokenClaimsSet idTokenClaimsSet = HandlerManager.getInstance().buildIDToken(messageContext);
        builder.setIdTokenClaimsSet(idTokenClaimsSet);
    }
}
