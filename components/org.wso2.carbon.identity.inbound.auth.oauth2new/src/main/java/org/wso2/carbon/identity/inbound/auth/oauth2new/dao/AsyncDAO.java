//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.wso2.carbon.identity.inbound.auth.oauth2new.dao;

import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.AccessTokenPersistenceTask.AccessTokenJob;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.AuthzCodePersistenceTask.AuthzCodeJob;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationMessageContext;

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
    public AccessToken getLatestActiveOrExpiredAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                                           Set<String> scopes, OAuth2MessageContext messageContext) {
        return persistentDAO.getLatestActiveOrExpiredAccessToken(consumerKey, authzUser, scopes, messageContext);
    }

    @Override
    public void storeAccessToken(AccessToken newAccessToken, String oldAccessToken, String authzCode,
                                 OAuth2MessageContext messageContext) {
        AccessTokenJob job = new AccessTokenJob(newAccessToken);
        job.oldAccessToken = oldAccessToken;
        job.authzCode = authzCode;
        job.messageContext = messageContext;
        accessTokenJobs.add(job);
    }

    @Override
    public String getAccessTokenByAuthzCode(String authorizationCode, OAuth2MessageContext messageContext) {
        return persistentDAO.getAccessTokenByAuthzCode(authorizationCode, messageContext);
    }

    @Override
    public void updateAccessTokenState(String accessToken, String tokenState,
                                       OAuth2TokenMessageContext messageContext) {
        persistentDAO.updateAccessTokenState(accessToken, tokenState, messageContext);
    }

    @Override
    public AccessToken getLatestAccessTokenByRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {
        return persistentDAO.getLatestAccessTokenByRefreshToken(refreshToken, messageContext);
    }

    @Override
    public void storeAuthzCode(AuthzCode authzCode, OAuth2MessageContext messageContext) {
        AuthzCodeJob job = new AuthzCodeJob(authzCode);
        job.messageContext = messageContext;
        authzCodeJobs.add(job);
    }

    @Override
    public AuthzCode getAuthzCode(String authzCode, OAuth2MessageContext messageContext) {
        return persistentDAO.getAuthzCode(authzCode, messageContext);
    }

    @Override
    public void updateAuthzCodeState(String authzCode, String state, OAuth2MessageContext messageContext) {
        AuthzCodeJob job = new AuthzCodeJob(authzCode, state);
        job.messageContext = messageContext;
        authzCodeJobs.add(job);
    }

    @Override
    public Set<String> getAuthorizedClientIDs(AuthenticatedUser authzUser, RevocationMessageContext messageContext) {
        return persistentDAO.getAuthorizedClientIDs(authzUser, messageContext);
    }

    @Override
    public AccessToken getAccessToken(String bearerToken, OAuth2MessageContext messageContext) {
        return persistentDAO.getAccessToken(bearerToken, messageContext);
    }

    @Override
    public void revokeAccessToken(String accessToken, RevocationMessageContext messageContext) {
        persistentDAO.revokeAccessToken(accessToken, messageContext);
    }

    @Override
    public void revokeRefreshToken(String refreshToken, RevocationMessageContext messageContext) {
        persistentDAO.revokeRefreshToken(refreshToken, messageContext);
    }
}
