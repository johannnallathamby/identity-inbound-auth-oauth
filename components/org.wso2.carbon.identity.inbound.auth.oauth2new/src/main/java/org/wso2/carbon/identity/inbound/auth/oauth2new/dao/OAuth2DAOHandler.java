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

package org.wso2.carbon.identity.inbound.auth.oauth2new.dao;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.handler.IdentityMessageHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;

import java.util.Set;

/*
 * For plugging in multiple OAuth2DAOs in runtime
 */
public final class OAuth2DAOHandler extends OAuth2DAO implements IdentityMessageHandler {

    private OAuth2DAO wrappedDAO = null;

    private IdentityMessageHandler identityHandler = new AbstractIdentityMessageHandler() {
        @Override
        public String getName() {
            return "DefaultOAuth2DAOHandler";
        }
    };

    /*
     * Will use DefaultOAuth2DAOHandler
     */
    public OAuth2DAOHandler(OAuth2DAO oauth2DAO) {
        if(oauth2DAO == null){
            throw new IllegalArgumentException("OAuth2DAO is NULL");
        }
        this.wrappedDAO = oauth2DAO;
    }

    /*
     * Will use OAuth2DAOHandler that was passed in
     */
    public OAuth2DAOHandler(OAuth2DAO oauth2DAO, IdentityMessageHandler identityHandler) {
        if(oauth2DAO == null){
            throw new IllegalArgumentException("OAuth2DAO is NULL");
        } else if (identityHandler == null) {
            throw new IllegalArgumentException("IdentityHandler is NULL");
        }
        this.wrappedDAO = oauth2DAO;
        this.identityHandler = identityHandler;
    }

    @Override
    public void init(InitConfig initConfig) {
        identityHandler.init(initConfig);
    }

    @Override
    public String getName() {
        return identityHandler.getName();
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {
        return identityHandler.isEnabled(messageContext);
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return identityHandler.getPriority(messageContext);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return identityHandler.canHandle(messageContext);
    }

    @Override
    public AccessToken getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                            Set<String> scopes, Set<String> states,
                                            OAuth2MessageContext messageContext) {
        return wrappedDAO.getLatestAccessToken(consumerKey, authzUser, scopes, states, messageContext);
    }

    @Override
    public void storeAccessToken(AccessToken newAccessToken, String oldAccessToken, String authzCode,
                                 OAuth2MessageContext messageContext) {
        wrappedDAO.storeAccessToken(newAccessToken, oldAccessToken, authzCode, messageContext);
    }

    public void updateAccessTokenState(String accessToken, String tokenState,
                                                TokenMessageContext messageContext) {
        wrappedDAO.updateAuthzCodeState(accessToken, tokenState, messageContext);
    }

    @Override
    public String getAccessTokenByAuthzCode(String authorizationCode, OAuth2MessageContext messageContext) {
        return wrappedDAO.getAccessTokenByAuthzCode(authorizationCode, messageContext);
    }

    @Override
    public AccessToken getLatestAccessTokenByRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {
        return wrappedDAO.getLatestAccessTokenByRefreshToken(refreshToken, messageContext);
    }

    @Override
    public void storeAuthzCode(AuthzCode authzCode, OAuth2MessageContext messageContext) {
        wrappedDAO.storeAuthzCode(authzCode, messageContext);
    }

    @Override
    public AuthzCode getAuthzCode(String authzCode, OAuth2MessageContext messageContext) {
        return wrappedDAO.getAuthzCode(authzCode, messageContext);
    }

    @Override
    public void updateAuthzCodeState(String authzCode, String state, OAuth2MessageContext messageContext) {
        wrappedDAO.updateAuthzCodeState(authzCode, state, messageContext);
    }

    @Override
    public Set<AccessToken> getAuthorizedAccessTokens(AuthenticatedUser authzUser, OAuth2MessageContext messageContext) {
        return wrappedDAO.getAuthorizedAccessTokens(authzUser, messageContext);
    }

    @Override
    public AccessToken getAccessToken(String bearerToken, OAuth2MessageContext messageContext) {
        return wrappedDAO.getAccessToken(bearerToken, messageContext);
    }

    @Override
    public void revokeAccessToken(String accessToken, OAuth2MessageContext messageContext) {
        wrappedDAO.revokeAccessToken(accessToken, messageContext);
    }

    @Override
    public void revokeRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {
        wrappedDAO.revokeRefreshToken(refreshToken, messageContext);
    }

    @Override
    public Set<AccessToken> getAccessTokensByClientId(String clientId, boolean includeExpired) {
        return wrappedDAO.getAccessTokensByClientId(clientId, includeExpired);
    }

    @Override
    public Set<AuthzCode> getAuthorizationCodesByClientId(String clientId, boolean includeExpired) {
        return wrappedDAO.getAuthorizationCodesByClientId(clientId, includeExpired);
    }

    @Override
    public Set<AccessToken> getAccessTokensOfTenant(String tenantDomain, boolean includeExpired) {
        return wrappedDAO.getAccessTokensOfTenant(tenantDomain, includeExpired);
    }

    @Override
    public Set<AuthzCode> getAuthorizationCodesOfTenant(String tenantDomain, boolean includeExpired) {
        return wrappedDAO.getAuthorizationCodesOfTenant(tenantDomain, includeExpired);
    }

    @Override
    public Set<AccessToken> getAccessTokensOfUserStore(String tenantDomain, String userStoreDomain,
                                                       boolean includeExpired) {
        return wrappedDAO.getAccessTokensOfUserStore(tenantDomain, userStoreDomain, includeExpired);
    }

    @Override
    public Set<AuthzCode> getAuthorizationCodesOfUserStore(String tenantDomain, String userStoreDomain,
                                                           boolean includeExpired) {
        return wrappedDAO.getAuthorizationCodesOfUserStore(tenantDomain, userStoreDomain, includeExpired);
    }

    @Override
    public void renameUserStore(String tenantDomain, String currentName, String newName) {
        wrappedDAO.renameUserStore(tenantDomain, currentName, newName);
    }
}
