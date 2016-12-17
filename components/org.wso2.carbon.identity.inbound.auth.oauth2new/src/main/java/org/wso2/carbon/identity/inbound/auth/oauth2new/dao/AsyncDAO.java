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

import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.AccessTokenPersistenceTask.AccessTokenJob;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.AuthzCodePersistenceTask.AuthzCodeJob;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;

import java.util.Set;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;

public class AsyncDAO extends OAuth2DAO {

    private static final Log log = LogFactory.getLog(AsyncDAO.class);

    private OAuth2DAO persistentDAO = null;
    private int poolSize = 0;

    private static BlockingDeque<AccessTokenJob> accessTokenJobs = new LinkedBlockingDeque<>();
    private static BlockingDeque<AuthzCodeJob> authzCodeJobs = new LinkedBlockingDeque<>();

    public AsyncDAO(OAuth2DAO persistentDAO) {

        this.persistentDAO = persistentDAO;

        String poolSizeConfig = IdentityUtil.getProperty("JDBCPersistenceManager.SessionDataPersist.PoolSize");
        if (NumberUtils.isNumber(poolSizeConfig)) {
            poolSize = Integer.parseInt(poolSizeConfig);
            if(log.isDebugEnabled()) {
                log.debug("Thread pool size for OAuth2 Async DAO: " + poolSizeConfig);
            }
        }
        if (poolSize > 0) {
            ExecutorService threadPool = Executors.newFixedThreadPool(poolSize);
            for (int i = 0; i < poolSize; i++) {
                threadPool.execute(new AccessTokenPersistenceTask(accessTokenJobs, persistentDAO));
            }
            threadPool = Executors.newFixedThreadPool(poolSize);
            for (int i = 0; i < poolSize; i++) {
                threadPool.execute(new AuthzCodePersistenceTask(authzCodeJobs, persistentDAO));
            }
        }
    }

    @Override
    public AccessToken getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                            Set<String> scopes, Set<String> states,
                                            OAuth2MessageContext messageContext) {
        return persistentDAO.getLatestAccessToken(consumerKey, authzUser, scopes, states,
                                                  messageContext);
    }

    @Override
    public void storeAccessToken(AccessToken newAccessToken, boolean markAccessTokenExpired,
                                 boolean markAccessTokenInactive, String oldAccessToken, String authzCode,
                                 OAuth2MessageContext messageContext) {
        if(poolSize > 0) {
            AccessTokenJob job = new AccessTokenJob(newAccessToken);
            job.oldAccessToken = oldAccessToken;
            job.authzCode = authzCode;
            job.messageContext = messageContext;
            accessTokenJobs.add(job);
        } else {
            persistentDAO.storeAccessToken(newAccessToken, markAccessTokenExpired, markAccessTokenInactive,
                                           oldAccessToken, authzCode, messageContext);
        }
    }

    @Override
    public String getAccessTokenByAuthzCode(String authorizationCode, OAuth2MessageContext messageContext) {
        return persistentDAO.getAccessTokenByAuthzCode(authorizationCode, messageContext);
    }

    @Override
    public void updateAccessTokenState(String accessToken, String tokenState,
                                       TokenMessageContext messageContext) {
        persistentDAO.updateAccessTokenState(accessToken, tokenState, messageContext);
    }

    @Override
    public AccessToken getLatestAccessTokenByRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {
        return persistentDAO.getLatestAccessTokenByRefreshToken(refreshToken, messageContext);
    }

    @Override
    public void storeAuthzCode(AuthzCode authzCode, OAuth2MessageContext messageContext) {
        if(poolSize > 0) {
            AuthzCodeJob job = new AuthzCodeJob(authzCode);
            job.messageContext = messageContext;
            authzCodeJobs.add(job);
        } else {
            persistentDAO.storeAuthzCode(authzCode, messageContext);
        }
    }

    @Override
    public AuthzCode getAuthzCode(String authzCode, OAuth2MessageContext messageContext) {
        return persistentDAO.getAuthzCode(authzCode, messageContext);
    }

    @Override
    public void updateAuthzCodeState(String authzCode, String state, OAuth2MessageContext messageContext) {
        if(poolSize > 0) {
            AuthzCodeJob job = new AuthzCodeJob(authzCode, state);
            job.messageContext = messageContext;
            authzCodeJobs.add(job);
        } else {
            persistentDAO.updateAuthzCodeState(authzCode, state, messageContext);
        }
    }

    @Override
    public Set<AccessToken> getAuthorizedAccessTokens(AuthenticatedUser authzUser, OAuth2MessageContext
            messageContext) {
        return persistentDAO.getAuthorizedAccessTokens(authzUser, messageContext);
    }

    @Override
    public AccessToken getAccessToken(String bearerToken, OAuth2MessageContext messageContext) {
        return persistentDAO.getAccessToken(bearerToken, messageContext);
    }

    @Override
    public void revokeAccessToken(String accessToken, OAuth2MessageContext messageContext) {
        persistentDAO.revokeAccessToken(accessToken, messageContext);
    }

    @Override
    public void revokeRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {
        persistentDAO.revokeRefreshToken(refreshToken, messageContext);
    }

    @Override
    public Set<AccessToken> getAccessTokensByClientId(String clientId, boolean includeExpired) {
        return persistentDAO.getAccessTokensByClientId(clientId, includeExpired);
    }

    @Override
    public Set<AuthzCode> getAuthorizationCodesByClientId(String clientId, boolean includeExpired) {
        return persistentDAO.getAuthorizationCodesByClientId(clientId, includeExpired);
    }

    @Override
    public Set<AccessToken> getAccessTokensOfTenant(String tenantDomain, boolean includeExpired) {
        return persistentDAO.getAccessTokensOfTenant(tenantDomain, includeExpired);
    }

    @Override
    public Set<AuthzCode> getAuthorizationCodesOfTenant(String tenantDomain, boolean includeExpired) {
        return persistentDAO.getAuthorizationCodesOfTenant(tenantDomain, includeExpired);
    }

    @Override
    public Set<AccessToken> getAccessTokensOfUserStore(String tenantDomain, String userStoreDomain,
                                                       boolean includeExpired) {
        return persistentDAO.getAccessTokensOfUserStore(tenantDomain, userStoreDomain, includeExpired);
    }

    @Override
    public Set<AuthzCode> getAuthorizationCodesOfUserStore(String tenantDomain, String userStoreDomain,
                                                           boolean includeExpired) {
        return persistentDAO.getAuthorizationCodesOfUserStore(tenantDomain, userStoreDomain, includeExpired);
    }

    @Override
    public void renameUserStore(String tenantDomain, String currentName, String newName) {
        persistentDAO.renameUserStore(tenantDomain, currentName, newName);
    }
}
