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

package org.wso2.carbon.identity.inbound.auth.oauth2new.dao.jdbc;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.AccessTokenExistsException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist.TokenPersistenceProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.UTC;

public class JDBCOAuth2DAO extends OAuth2DAO {

    private static final Log log = LogFactory.getLog(JDBCOAuth2DAO.class);

    private static final String AUTHZ_USER = "AUTHZ_USER";
    private static final String LOWER_AUTHZ_USER = "LOWER(AUTHZ_USER)";

    @Override
    public AccessToken getLatestAccessToken(String clientId, AuthenticatedUser authzUser,
                                            Set<String> scopes, Set<String> states,
                                            OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            return getLatestAccessToken(connection, clientId, authzUser, scopes, states, messageContext);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    protected AccessToken getLatestAccessToken(Connection connection, String clientId, AuthenticatedUser authzUser,
                                            Set<String> scopes, Set<String> states,
                                            OAuth2MessageContext messageContext) {

        if(CollectionUtils.isEmpty(states)) {
            throw new IllegalArgumentException("States cannot be empty.");
        }
        for(String state:states) {
            OAuth2.TokenState.validate(state);
        }

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        try {
            String sql;
            if (connection.getMetaData().getDriverName().contains("MySQL")
                || connection.getMetaData().getDriverName().contains("H2")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MYSQL;
            } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_DB2SQL;
            } else if (connection.getMetaData().getDriverName().contains("MS SQL")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
            } else if (connection.getMetaData().getDriverName().contains("Microsoft")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_MSSQL;
            } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_POSTGRESQL;
            } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_INFORMIX;

            } else {
                sql = SQLQueries.RETRIEVE_LATEST_ACCESS_TOKEN_BY_CLIENT_ID_USER_SCOPE_ORACLE;
            }

            StringBuilder sb = new StringBuilder("TOKEN_SCOPE_HASH=?");
            if(states.contains(OAuth2.TokenState.ACTIVE) || states.contains(OAuth2.TokenState.EXPIRED) || states
                    .contains(OAuth2.TokenState.INACTIVE) || states.contains(OAuth2.TokenState.REVOKED)) {
                sb.append(" AND (");
            }
            if(states.contains(OAuth2.TokenState.ACTIVE)) {
                sb.append("TOKEN_STATE='ACTIVE'");
            }
            if(states.contains(OAuth2.TokenState.EXPIRED)) {
                sb.append(" AND TOKEN_STATE='EXPIRED'");
            }
            if(states.contains(OAuth2.TokenState.INACTIVE)) {
                sb.append(" AND TOKEN_STATE='INACTIVE'");
            }
            if(states.contains(OAuth2.TokenState.REVOKED)) {
                sb.append(" AND TOKEN_STATE='REVOKED'");
            }
            if(states.contains(OAuth2.TokenState.ACTIVE) || states.contains(OAuth2.TokenState.EXPIRED) || states
                    .contains(OAuth2.TokenState.INACTIVE) || states.contains(OAuth2.TokenState.REVOKED)) {
                sb.append(")");
            }
            sql = sql.replace("TOKEN_SCOPE_HASH=?", sb.toString());

            if (!isUsernameCaseSensitive){
                sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }

            String hashedScope = OAuth2Util.hashScopes(scopes);
            if (hashedScope == null) {
                sql = sql.replace("TOKEN_SCOPE_HASH=?", "TOKEN_SCOPE_HASH IS NULL");
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, processor.getProcessedClientId(clientId));
            if (isUsernameCaseSensitive) {
                prepStmt.setString(2, authzUser.getUserName());
            } else {
                prepStmt.setString(2, authzUser.getUserName().toLowerCase());
            }
            prepStmt.setInt(3, IdentityTenantUtil.getTenantId(authzUser.getTenantDomain()));
            prepStmt.setString(4, authzUser.getUserStoreDomain());
            prepStmt.setString(5, authzUser.getAuthenticatedSubjectIdentifier());

            if (hashedScope != null) {
                prepStmt.setString(5, hashedScope);
            }

            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                String accessTokenId = processor.getPreprocessedAccessToken(
                        resultSet.getString(1));
                String refreshToken = null;
                if (resultSet.getString(2) != null) {
                    refreshToken = processor.getPreprocessedRefreshToken(resultSet.getString(2));
                }
                long issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone("UTC")))
                        .getTime();
                long refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone
                        ("UTC"))).getTime();
                long validityPeriod = resultSet.getLong(5);
                long refreshTokenValidityPeriod = resultSet.getLong(6);
                String tokenId = resultSet.getString(7);
                String grantType = resultSet.getString(8);
                String state = resultSet.getString(9);
                AccessToken accessToken = new AccessToken(accessTokenId, clientId, authzUser
                        .getAuthenticatedSubjectIdentifier(), grantType, state, new Timestamp(issuedTime),
                                                          validityPeriod);
                accessToken.setAuthzUser(authzUser);
                accessToken.setScopes(scopes);
                accessToken.setAccessTokenId(tokenId);
                accessToken.setRefreshToken(refreshToken);
                accessToken.setRefreshTokenIssuedTime(new Timestamp(refreshTokenIssuedTime));
                accessToken.setRefreshTokenValidity(refreshTokenValidityPeriod);
                return accessToken;
            }
            return null;
        } catch (SQLException e) {
            String errorMsg = "Error occurred while trying to retrieve latest access token for " + OAuth2Util
                    .createUniqueAuthzGrantString(authzUser, clientId, scopes) + " with state either of " + states;
            throw OAuth2RuntimeException.error(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(null, resultSet, prepStmt);
        }
    }

    @Override
    public void storeAccessToken(AccessToken newAccessToken, String oldAccessToken,
                                 String authzCode, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();

        // can we generate this access_token_id before hand and save it in authz_code table ?
        String accessTokenId = UUID.randomUUID().toString();
        newAccessToken.setAccessTokenId(accessTokenId);

        try {
            if (oldAccessToken != null) {
                updateAccessTokenState(connection, oldAccessToken, OAuth2.TokenState.EXPIRED, messageContext);
            }
            if (authzCode != null) {
                updateAuthzCodeState(connection, authzCode, OAuth2.TokenState.INACTIVE, messageContext);
            }
            storeAccessToken(connection, newAccessToken, OAuth2ServerConfig.getInstance()
                    .getTokenPersistenceRetryCount(), messageContext);
            updateAccessTokenForAuthzCode(connection, authzCode, accessTokenId, messageContext);
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error occurred while storing access token for " + OAuth2Util
                    .createUniqueAuthzGrantString(newAccessToken), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, null);
        }
    }

    protected void storeAccessToken(Connection connection, AccessToken newAccessToken, int retryCount,
                                    OAuth2MessageContext messageContext) {

        if(retryCount == 0) {
            return;
        } else {
            retryCount--;
        }
        String sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN;
        String sqlAddScopes = SQLQueries.INSERT_OAUTH2_TOKEN_SCOPE;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, processor.getProcessedAccessToken(newAccessToken.getAccessToken()));
            prepStmt.setString(2, processor.getProcessedRefreshToken(newAccessToken.getRefreshToken()));
            prepStmt.setString(3, newAccessToken.getAuthzUser().getUserName());
            int tenantId = IdentityTenantUtil.getTenantId(newAccessToken.getAuthzUser().getTenantDomain());
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, newAccessToken.getAuthzUser().getUserStoreDomain());
            prepStmt.setTimestamp(6, newAccessToken.getAccessTokenIssuedTime(), Calendar.getInstance(TimeZone.getTimeZone("UTC")));
            prepStmt.setTimestamp(7, newAccessToken.getRefreshTokenIssuedTime(), Calendar.getInstance(TimeZone
                                                                                                              .getTimeZone("UTC")));
            prepStmt.setLong(8, newAccessToken.getAccessTokenValidity());
            prepStmt.setLong(9, newAccessToken.getRefreshTokenValidity());
            prepStmt.setString(10, OAuth2Util.hashScopes(newAccessToken.getScopes()));
            prepStmt.setString(11, newAccessToken.getAccessTokenState());
            prepStmt.setString(13, newAccessToken.getAccessTokenId());
            prepStmt.setString(14, newAccessToken.getGrantType());
            prepStmt.setString(15, newAccessToken.getAuthzUser().getAuthenticatedSubjectIdentifier());
            prepStmt.setString(16, processor.getProcessedClientId(newAccessToken.getClientId()));
            prepStmt.execute();

            prepStmt = connection.prepareStatement(sqlAddScopes);

            if (CollectionUtils.isNotEmpty(newAccessToken.getScopes())) {
                for (String scope : newAccessToken.getScopes()) {
                    prepStmt.setString(1, newAccessToken.getAccessTokenId());
                    prepStmt.setString(2, scope);
                    prepStmt.setInt(3, tenantId);
                    prepStmt.execute();
                }
            }

            if((Boolean) messageContext.getParameter("RetryingTokenPersistence")) {
                log.info("Successfully recovered from 'CON_APP_KEY' constraint violation in " + (5 - retryCount) +
                         " attempt(s) for " + OAuth2Util.createUniqueAuthzGrantString(newAccessToken));
            }

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            // Handle constraint violation in JDBC drivers which do not throw SQLIntegrityConstraintViolationException
            if(e instanceof SQLIntegrityConstraintViolationException || e.getMessage().contains("CON_APP_KEY")) {

                Set<String> activeState = new HashSet();
                activeState.add(OAuth2.TokenState.ACTIVE);

                Set<String> nonActiveStates = new HashSet();
                nonActiveStates.add(OAuth2.TokenState.EXPIRED);
                nonActiveStates.add(OAuth2.TokenState.INACTIVE);
                nonActiveStates.add(OAuth2.TokenState.REVOKED);


                AccessToken activeAccessToken = getLatestAccessToken(newAccessToken.getClientId(),
                                                                     newAccessToken.getAuthzUser(),
                                                                     newAccessToken.getScopes(), activeState,
                                                                     messageContext);

                AccessToken nonActiveAccessToken = getLatestAccessToken(newAccessToken.getClientId(),
                                                                        newAccessToken.getAuthzUser(),
                                                                        newAccessToken.getScopes(), nonActiveStates,
                                                                        messageContext);

                if (activeAccessToken != null) {
                    if (nonActiveAccessToken == null ||
                        activeAccessToken.getAccessTokenIssuedTime().after(
                                nonActiveAccessToken.getAccessTokenIssuedTime())) {
                        if (getPoolSize() == 0) {
                            // In here we can use existing token since we have a synchronised communication
                            log.info("Successfully recovered from 'CON_APP_KEY' constraint violation in " + (5-retryCount) +
                                     " attempt(s) for " + OAuth2Util.createUniqueAuthzGrantString(newAccessToken));
                            throw AccessTokenExistsException.error(activeAccessToken, e);
                        } else {
                            // In here we have to use new token since we have asynchronous communication. User already
                            // received that token

                            // Inactivate latest active token.
                            updateAccessTokenState(connection, activeAccessToken.getAccessToken(), OAuth2.TokenState
                                    .INACTIVE, messageContext);

                            // Update token issued time make this token as latest token & try to store it again.
                            newAccessToken = updateTokenIssuedTime(newAccessToken);
                            messageContext.addParameter("RetryingTokenPersistence", true);
                            storeAccessToken(connection, newAccessToken, retryCount, messageContext);
                        }
                    } else {
                        // Inactivate latest active token.
                        updateAccessTokenState(connection, activeAccessToken.getAccessToken(), OAuth2.TokenState
                                .INACTIVE, messageContext);

                        // Update token issued time and make this token as the latest token & try to store it again.
                        newAccessToken = updateTokenIssuedTime(newAccessToken);
                        messageContext.addParameter("RetryingTokenPersistence", true);
                        storeAccessToken(connection, newAccessToken, retryCount, messageContext);
                    }
                } else {

                    // In this case another process already updated the latest active token to inactive.
                    // Update token issued time make this token as latest token & try to store it again.
                    newAccessToken = updateTokenIssuedTime(newAccessToken);
                    messageContext.addParameter("RetryingTokenPersistence", true);
                    storeAccessToken(connection, newAccessToken, retryCount, messageContext);
                }
                if(retryCount == 0) {
                    String errorMsg = "Couldn't recover from 'CON_APP_KEY' constraint violation within maximum retry count " +
                                      OAuth2ServerConfig.getInstance().getTokenPersistenceRetryCount() + " for " + OAuth2Util
                                              .createUniqueAuthzGrantString(newAccessToken);
                    throw OAuth2RuntimeException.error(errorMsg, e);
                }
            }
            throw OAuth2RuntimeException.error("Error occurred while storing access token", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(null, null, prepStmt);
        }
    }

    @Override
    public String getAccessTokenByAuthzCode(String authorizationCode, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        String sqlQuery = SQLQueries.GET_ACCESS_TOKEN_BY_CODE;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement ps = null;
        String accessToken = null;
        try {
            if(connection.getMetaData().getDriverName().contains("MySQL")){
                sqlQuery = SQLQueries.GET_ACCESS_TOKEN_BY_CODE_MYSQL ;
            }
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, processor.getProcessedAuthzCode(authorizationCode));
            ResultSet resultSet = ps.executeQuery();
            while(resultSet.next()){
                accessToken = resultSet.getString(1);
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return accessToken;
    }

    @Override
    public void updateAccessTokenState(String accessToken, String tokenState, TokenMessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            updateAccessTokenState(connection, accessToken, tokenState, messageContext);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    protected void updateAccessTokenState(Connection connection, String accessToken, String tokenState,
                                          OAuth2MessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement prepStmt = null;
        try {
            String sql = SQLQueries.UPDATE_ACCESS_TOKEN_STATE;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, tokenState);
            prepStmt.setString(2, UUID.randomUUID().toString());
            prepStmt.setString(3, processor.getProcessedAccessToken(accessToken));
            prepStmt.executeUpdate();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    @Override
    public AccessToken getLatestAccessTokenByRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {

        AccessToken accessToken = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = null;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        try {
            String mySqlQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MYSQL;
            String db2Query = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_DB2SQL;
            String oracleQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_ORACLE;
            String msSqlQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MSSQL;
            String informixQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_INFORMIX;
            String postgreSqlQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_POSTGRESQL;

            if (connection.getMetaData().getDriverName().contains("MySQL")
                    || connection.getMetaData().getDriverName().contains("H2")) {
                sql = mySqlQuery;
            } else if(connection.getMetaData().getDatabaseProductName().contains("DB2")){
                sql = db2Query;
            } else if (connection.getMetaData().getDriverName().contains("MS SQL")) {
                sql = msSqlQuery;
            } else if (connection.getMetaData().getDriverName().contains("Microsoft")) {
                sql = msSqlQuery;
            } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                sql = postgreSqlQuery;
            } else if (connection.getMetaData().getDriverName().contains("INFORMIX")) {
                sql = informixQuery;
            } else {
                sql = oracleQuery;
            }

            if (refreshToken == null) {
                sql = sql.replace("REFRESH_TOKEN = ?", "REFRESH_TOKEN IS NULL");
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, processor.getProcessedRefreshToken(refreshToken));
            resultSet = prepStmt.executeQuery();
            int iterateId = 0;
            String accessTokenId = null;
            String bearerToken = null;
            String userName = null;
            int tenantId;
            String userDomain = null;
            Set<String> scopeSet = new HashSet<>();
            String accessTokenState = null;
            Timestamp accessTokenIssuedTime = null;
            long accessTokenValidity = -1l;
            Timestamp refreshTokenIssuedTime = null;
            long refreshTokenValidity = -1l;
            String grantType = null;
            String subjectIdentifier = null;
            String clientId = null;
            AuthenticatedUser user = new AuthenticatedUser();
            while (resultSet.next()) {
                if (iterateId == 0) {
                    accessTokenId = resultSet.getString(1);
                    bearerToken = processor.getPreprocessedAccessToken(
                            resultSet.getString(2));
                    userName = resultSet.getString(3);
                    tenantId = resultSet.getInt(4);
                    userDomain = resultSet.getString(5);
                    scopeSet = OAuth2Util.buildScopeSet(resultSet.getString(6));
                    accessTokenState = resultSet.getString(7);
                    accessTokenIssuedTime = resultSet.getTimestamp(8,
                            Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                    accessTokenValidity = resultSet.getLong(9);
                    refreshTokenIssuedTime = resultSet.getTimestamp(10);
                    refreshTokenValidity = resultSet.getLong(11);
                    grantType = resultSet.getString(12);
                    subjectIdentifier = resultSet.getString(13);
                    clientId = resultSet.getString(14);
                    user.setUserName(userName);
                    user.setUserStoreDomain(userDomain);
                    user.setTenantDomain(IdentityTenantUtil.getTenantDomain(tenantId));
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
                } else {
                    scopeSet.add(resultSet.getString(6));
                }
                iterateId++;
            }
            if(bearerToken != null){
                accessToken = new AccessToken(bearerToken, clientId, subjectIdentifier, grantType,
                        accessTokenState, accessTokenIssuedTime, accessTokenValidity);
                if(!scopeSet.isEmpty()) {
                    accessToken.setScopes(scopeSet);
                }
                accessToken.setRefreshToken(refreshToken);
                accessToken.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                accessToken.setRefreshTokenValidity(refreshTokenValidity);
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error when validating a refresh token", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return accessToken;
    }

    @Override
    public void storeAuthzCode(AuthzCode authzCode, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);

        String authzCodeId = UUID.randomUUID().toString();
        authzCode.setAuthzCodeId(authzCodeId);

        try {
            prepStmt = connection.prepareStatement(SQLQueries.STORE_AUTHORIZATION_CODE);
            prepStmt.setString(1, authzCodeId);
            prepStmt.setString(2, processor.getProcessedAuthzCode(authzCode.getAuthzCode()));
            prepStmt.setString(3, authzCode.getRedirectURI());
            prepStmt.setString(4, OAuth2Util.buildScopeString(authzCode.getScopes()));
            prepStmt.setString(5, authzCode.getAuthzUser().getUserName());
            prepStmt.setString(6, authzCode.getAuthzUser().getUserStoreDomain());
            int tenantId = IdentityTenantUtil.getTenantId(authzCode.getAuthzUser().getTenantDomain());
            prepStmt.setInt(7, tenantId);
            prepStmt.setTimestamp(8, authzCode.getIssuedTime(),
                    Calendar.getInstance(TimeZone.getTimeZone("UTC")));
            prepStmt.setLong(9, authzCode.getValidityPeriod());
            prepStmt.setString(10, authzCode.getAuthzUser().getAuthenticatedSubjectIdentifier());
            prepStmt.setString(11, authzCode.getPkceCodeChallenge());
            prepStmt.setString(12, authzCode.getPkceCodeChallengeMethod());
            prepStmt.setString(13, processor.getPreprocessedClientId(authzCode.getClientId()));

            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error when storing the authorization code for consumer key : " +
                    authzCode.getClientId(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    @Override
    public AuthzCode getAuthzCode(String authzCode, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        AuthzCode authorizationCode = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.RETRIEVE_AUTHZ_CODE);
            prepStmt.setString(1, processor.getProcessedAuthzCode(authzCode));
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                String authzCodeId = resultSet.getString(1);
                String authorizedUser = resultSet.getString(2);
                String userStoreDomain = resultSet.getString(3);
                int tenantId = resultSet.getInt(4);
                String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
                String scopeString = resultSet.getString(5);
                String redirectUri = resultSet.getString(6);
                Timestamp issuedTime = resultSet.getTimestamp(7, Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                long validityPeriod = resultSet.getLong(8);
                String codeState = resultSet.getString(9);
                String subjectIdentifier = resultSet.getString(10);
                String clientId = resultSet.getString(11);
                String pkceCodeChallenge = resultSet.getString(12);
                String pkceCodeChallengeMethod = resultSet.getString(13);
                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(authorizedUser);
                user.setTenantDomain(tenantDomain);
                user.setUserStoreDomain(userStoreDomain);
                user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
                authorizationCode =  new AuthzCode(authzCode, clientId, redirectUri, subjectIdentifier,
                        issuedTime, validityPeriod, codeState);
                authorizationCode.setAuthzCodeId(authzCodeId);
                authorizationCode.setAuthzUser(user);
                authorizationCode.setScopes(OAuth2Util.buildScopeSet(scopeString));
                authorizationCode.setPkceCodeChallenge(pkceCodeChallenge);
                authorizationCode.setPkceCodeChallengeMethod(pkceCodeChallengeMethod);
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error when validating an authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return authorizationCode;
    }

    @Override
    public void updateAuthzCodeState(String authzCode, String state, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            updateAuthzCodeState(connection, authzCode, state, messageContext);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    protected void updateAuthzCodeState(Connection connection, String authzCode,
                                     String state, OAuth2MessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.UPDATE_AUTHZ_CODE_STATE);
            prepStmt.setString(1, state);
            prepStmt.setString(2, processor.getProcessedAuthzCode(authzCode));
            prepStmt.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    protected void updateAccessTokenForAuthzCode(Connection connection, String authzCode,
                                                 String newAccessTokenId, OAuth2MessageContext messageContext) {

        PreparedStatement prepStmt = null;
        try {
            String sql;
            if (connection.getMetaData().getDriverName().contains("MySQL")){
                sql = SQLQueries.UPDATE_NEW_TOKEN_AGAINST_AUTHZ_CODE_MYSQL;
            } else{
                sql = SQLQueries.UPDATE_NEW_TOKEN_AGAINST_AUTHZ_CODE;
            }
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, newAccessTokenId);
            prepStmt.setString(2, authzCode);
            prepStmt.executeUpdate();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error while updating Access Token against authorization code for " +
                    "access token with ID : " + newAccessTokenId, e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    // need to fix this method to return all authorized access tokens by user
    public Set<AccessToken> getAuthorizedAccessTokens(AuthenticatedUser authzUser, OAuth2MessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> distinctConsumerKeys = new HashSet<>();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = authzUser.getTenantDomain();
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        String userDomain = authzUser.getUserStoreDomain();
        if ((userDomain != null)){
            userDomain.toUpperCase();
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            String sqlQuery = SQLQueries.GET_DISTINCT_APPS_AUTHORIZED_BY_USER_ALL_TIME;
            if (!isUsernameCaseSensitive){
                sqlQuery = sqlQuery.replace("AUTHZ_USER", "LOWER(AUTHZ_USER)");
            }
            ps = connection.prepareStatement(sqlQuery);
            if (isUsernameCaseSensitive) {
                ps.setString(1, tenantAwareUsernameWithNoUserDomain);
            } else {
                ps.setString(1, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            ps.setInt(2, tenantId);
            ps.setString(3, userDomain);
            rs = ps.executeQuery();
            while (rs.next()) {
                String consumerKey = processor.getPreprocessedClientId(rs.getString(1));
                distinctConsumerKeys.add(consumerKey);
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error occurred while retrieving all distinct Client IDs " +
                    "authorized by AuthenticatedUser ID : " + authzUser + " until now", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return null;
    }

    public AccessToken getAccessToken(String bearerToken, OAuth2MessageContext messageContext) {

        AccessToken accessToken = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLQueries.RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        try {
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, processor.getProcessedAccessToken(bearerToken));
            resultSet = prepStmt.executeQuery();
            int iterateId = 0;
            Set<String> scopes = new HashSet<>();
            while (resultSet.next()) {
                if (iterateId == 0) {
                    String accessTokenId = resultSet.getString(1);
                    String clientId = processor.getPreprocessedClientId(resultSet.getString(2));
                    String authorizedUser = resultSet.getString(3);
                    int tenantId = resultSet.getInt(4);
                    String userDomain = resultSet.getString(5);
                    scopes.add(resultSet.getString(6));
                    Timestamp accessTokenIssuedTime = resultSet.getTimestamp(7,
                            Calendar.getInstance(TimeZone.getTimeZone
                                    ("UTC")));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(8,
                            Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                    long accessTokenValidity = resultSet.getLong(9);
                    long refreshTokenValidity = resultSet.getLong(10);
                    String refreshToken = resultSet.getString(11);
                    String grantType = resultSet.getString(12);
                    String subjectIdentifier = resultSet.getString(13);
                    String tokenState = resultSet.getString(14);

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(authorizedUser);
                    user.setUserStoreDomain(userDomain);
                    user.setTenantDomain(IdentityTenantUtil.getTenantDomain(tenantId));
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier);

                    accessToken = new AccessToken(bearerToken, clientId, subjectIdentifier, grantType, tokenState,
                            accessTokenIssuedTime, accessTokenValidity);
                    accessToken.setAccessTokenId(accessTokenId);
                    accessToken.setRefreshToken(refreshToken);
                    accessToken.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                    accessToken.setRefreshTokenValidity(refreshTokenValidity);
                } else {
                    scopes.add(resultSet.getString(6));
                }
                iterateId++;
            }
            if(!scopes.isEmpty()) {
                accessToken.setScopes(scopes);
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return accessToken;
    }

    public void revokeAccessToken(String accessToken, OAuth2MessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        String sqlQuery = SQLQueries.UPDATE_ACCESS_TOKEN_STATE;
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, OAuth2.TokenState.REVOKED);
            ps.setString(2, UUID.randomUUID().toString());
            ps.setString(3, processor.getProcessedAccessToken(accessToken));
            ps.execute();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }  finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    public void revokeRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        String sqlQuery = SQLQueries.REVOKE_REFRESH_TOKEN;
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, UUID.randomUUID().toString());
            ps.setString(2, processor.getProcessedRefreshToken(refreshToken));
            ps.execute();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }  finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    // need to fix this method to return all AccessToken objects
    public Set<AccessToken> getAccessTokensByClientId(String consumerKey, boolean includeExpired) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(null);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> accessTokens = new HashSet<>();
        try {
            String sqlQuery = SQLQueries.GET_ACCESS_TOKENS_FOR_CONSUMER_KEY;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setString(2, OAuth2.TokenState.ACTIVE);
            ps.setString(2, includeExpired ? OAuth2.TokenState.EXPIRED : OAuth2.TokenState.ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {
                accessTokens.add(processor.getPreprocessedAccessToken(rs.getString(1)));
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error occurred while retrieving access tokens for client Id: " +
                                               consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return null;
    }

    // need to fix this method to return all AuthzCode objects
    public Set<AuthzCode> getAuthorizationCodesByClientId(String consumerKey, boolean includeExpired) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(null);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> authorizationCodes = new HashSet<>();
        try {
            String sqlQuery = SQLQueries.GET_AUTHORIZATION_CODES_FOR_CONSUMER_KEY;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setString(2, OAuth2.TokenState.ACTIVE);
            ps.setString(3, includeExpired ? OAuth2.TokenState.EXPIRED : OAuth2.TokenState.ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {
                authorizationCodes.add(processor.getPreprocessedAuthzCode(rs.getString(1)));
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error occurred while getting authorization codes for client Id: " +
                                               consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return null;
    }

    /*
     * Following 6 methods are for tenant listener and userstore listener
     */
    public Set<AccessToken> getAccessTokensOfTenant(String tenantDomain, boolean includeExpired) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(null);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String,AccessToken> accessTokenMap = new HashMap();
        try {
            String sql = SQLQueries.LIST_ALL_TOKENS_IN_TENANT;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, IdentityTenantUtil.getTenantId(tenantDomain));
            prepStmt.setString(2, OAuth2.TokenState.ACTIVE);
            prepStmt.setString(3, includeExpired ? OAuth2.TokenState.EXPIRED : OAuth2.TokenState.ACTIVE);
            resultSet = prepStmt.executeQuery();
            while (resultSet.next()) {
                String tokenId = resultSet.getString(1);
                if(!accessTokenMap.containsKey(tokenId)) {
                    String accessTokenId = processor.getPreprocessedAccessToken(resultSet.getString(2));
                    String refreshToken = processor.getPreprocessedRefreshToken(resultSet.getString(3));
                    String clientId = resultSet.getString(4);
                    String authzUser = resultSet.getString(5);
                    String userStoreDomain = resultSet.getString(6);
                    Set<String> scope = OAuth2Util.buildScopeSet(resultSet.getString(7));
                    String state = resultSet.getString(8);
                    Timestamp issuedTime = resultSet.getTimestamp(9, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(10, Calendar.getInstance(TimeZone
                                                                                                               .getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(11);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(12);
                    String grantType = resultSet.getString(13);
                    String subjectIdentifier = resultSet.getString(14);

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(authzUser);
                    user.setUserStoreDomain(userStoreDomain);
                    user.setTenantDomain(tenantDomain);
                    AccessToken accessToken = new AccessToken(accessTokenId, clientId, subjectIdentifier, grantType,
                                                              state, issuedTime, validityPeriodInMillis);
                    accessToken.setScopes(scope);
                    accessToken.setAuthzUser(user);
                    accessToken.setRefreshToken(refreshToken);
                    accessToken.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                    accessToken.setRefreshTokenValidity(refreshTokenValidityPeriodMillis);
                    accessToken.setRefreshToken(refreshToken);
                    accessTokenMap.put(accessTokenId, accessToken);
                } else {
                    accessTokenMap.get(tokenId).getScopes().add(resultSet.getString(7));
                }
            }
            connection.commit();
            return new HashSet(accessTokenMap.values());
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving access tokens for " +
                              "tenant domain : " + tenantDomain;
            throw OAuth2RuntimeException.error(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    public Set<AuthzCode> getAuthorizationCodesOfTenant(String tenantDomain, boolean includeExpired) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(null);
        Connection connection = IdentityDatabaseUtil.getDBConnection();;
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<AuthzCode> authzCodes = new HashSet();
        try {
            String sqlQuery = SQLQueries.LIST_LATEST_AUTHZ_CODES_IN_TENANT;
            ps = connection.prepareStatement(sqlQuery);
            ps.setInt(1, IdentityTenantUtil.getTenantId(tenantDomain));
            ps.setString(2, OAuth2.TokenState.ACTIVE);
            ps.setString(3, includeExpired ? OAuth2.TokenState.EXPIRED : OAuth2.TokenState.ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {
                String authzCodeId = rs.getString(1);
                String code = processor.getPreprocessedAuthzCode(rs.getString(2));
                String clientId = rs.getString(3);
                String authzUser = rs.getString(4);
                Set<String> scopes = OAuth2Util.buildScopeSet(rs.getString(5));
                Timestamp issuedTime = rs.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long validityPeriodInMillis = rs.getLong(7);
                String callbackUrl = rs.getString(8);
                String userStoreDomain = rs.getString(9);
                String state = rs.getString(10);
                String subjectIdentifier = rs.getString(11);
                String pkceChallenge = rs.getString(12);
                String pkceChallengeMethod = rs.getString(13);

                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(authzUser);
                user.setUserStoreDomain(userStoreDomain);
                user.setTenantDomain(tenantDomain);
                AuthzCode authzCode = new AuthzCode(code, clientId, callbackUrl, subjectIdentifier, issuedTime,
                                                    validityPeriodInMillis, state);
                authzCode.setAuthzUser(user);
                authzCode.setScopes(scopes);
                authzCode.setAuthzCodeId(authzCodeId);
                authzCode.setPkceCodeChallenge(pkceChallenge);
                authzCode.setPkceCodeChallengeMethod(pkceChallengeMethod);
                authzCodes.add(authzCode);
            }
            connection.commit();
            return authzCodes;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error occurred while retrieving authorization codes of tenant domain:"
                                               + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
    }

    public Set<AccessToken> getAccessTokensOfUserStore(String tenantDomain, String userStoreDomain,
                                                       boolean includeExpired) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(null);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String,AccessToken> accessTokenMap = new HashMap();
        try {
            String sql = SQLQueries.LIST_ALL_TOKENS_IN_USER_STORE;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, IdentityTenantUtil.getTenantId(tenantDomain));
            prepStmt.setString(2, userStoreDomain);
            prepStmt.setString(3, OAuth2.TokenState.ACTIVE);
            prepStmt.setString(4, includeExpired ? OAuth2.TokenState.EXPIRED : OAuth2.TokenState.ACTIVE);
            resultSet = prepStmt.executeQuery();
            while (resultSet.next()) {
                String tokenId = resultSet.getString(1);
                if(!accessTokenMap.containsKey(tokenId)) {
                    String accessTokenId = processor.getPreprocessedAccessToken(resultSet.getString(2));
                    String refreshToken = processor.getPreprocessedRefreshToken(resultSet.getString(3));
                    String clientId = resultSet.getString(4);
                    String authzUser = resultSet.getString(5);
                    Set<String> scope = OAuth2Util.buildScopeSet(resultSet.getString(6));
                    String state = resultSet.getString(7);
                    Timestamp issuedTime = resultSet.getTimestamp(8, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(9, Calendar.getInstance(TimeZone
                                                                                                               .getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(10);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(11);
                    String grantType = resultSet.getString(12);
                    String subjectIdentifier = resultSet.getString(13);

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(authzUser);
                    user.setUserStoreDomain(userStoreDomain);
                    user.setTenantDomain(tenantDomain);
                    AccessToken accessToken = new AccessToken(accessTokenId, clientId, subjectIdentifier, grantType,
                                                              state, issuedTime, validityPeriodInMillis);
                    accessToken.setScopes(scope);
                    accessToken.setAuthzUser(user);
                    accessToken.setRefreshToken(refreshToken);
                    accessToken.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                    accessToken.setRefreshTokenValidity(refreshTokenValidityPeriodMillis);
                    accessToken.setRefreshToken(refreshToken);
                    accessTokenMap.put(accessTokenId, accessToken);
                } else {
                    accessTokenMap.get(tokenId).getScopes().add(resultSet.getString(6));
                }
            }
            connection.commit();
            return new HashSet(accessTokenMap.values());
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving access tokens for " +
                              "tenant domain : " + tenantDomain;
            throw OAuth2RuntimeException.error(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    public Set<AuthzCode> getAuthorizationCodesOfUserStore(String tenantDomain, String userStoreDomain, boolean
            includeExpired) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(null);
        Connection connection = IdentityDatabaseUtil.getDBConnection();;
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<AuthzCode> authzCodes = new HashSet();
        try {
            String sqlQuery = SQLQueries.LIST_LATEST_AUTHZ_CODES_IN_TENANT;
            ps = connection.prepareStatement(sqlQuery);
            ps.setInt(1, IdentityTenantUtil.getTenantId(tenantDomain));
            ps.setString(2, userStoreDomain);
            ps.setString(3, OAuth2.TokenState.ACTIVE);
            ps.setString(4, includeExpired ? OAuth2.TokenState.EXPIRED : OAuth2.TokenState.ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {
                String authzCodeId = rs.getString(1);
                String code = processor.getPreprocessedAuthzCode(rs.getString(2));
                String clientId = rs.getString(3);
                String authzUser = rs.getString(4);
                Set<String> scopes = OAuth2Util.buildScopeSet(rs.getString(5));
                Timestamp issuedTime = rs.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long validityPeriodInMillis = rs.getLong(7);
                String callbackUrl = rs.getString(8);
                String state = rs.getString(9);
                String subjectIdentifier = rs.getString(10);
                String pkceChallenge = rs.getString(11);
                String pkceChallengeMethod = rs.getString(12);

                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(authzUser);
                user.setUserStoreDomain(userStoreDomain);
                user.setTenantDomain(tenantDomain);
                AuthzCode authzCode = new AuthzCode(code, clientId, callbackUrl, subjectIdentifier, issuedTime,
                                                    validityPeriodInMillis, state);
                authzCode.setAuthzUser(user);
                authzCode.setScopes(scopes);
                authzCode.setAuthzCodeId(authzCodeId);
                authzCode.setPkceCodeChallenge(pkceChallenge);
                authzCode.setPkceCodeChallengeMethod(pkceChallengeMethod);
                authzCodes.add(authzCode);
            }
            connection.commit();
            return authzCodes;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error occurred while retrieving authorization codes of tenant domain:"
                                               + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
    }

    public void renameUserStore(String tenantDomain, String currentName, String newName) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps1 = null;
        PreparedStatement ps2 = null;
        try {

            String sqlQuery1 = SQLQueries.RENAME_USER_STORE_IN_ACCESS_TOKEN_TABLE;
            String sqlQuery2 = SQLQueries.RENAME_USER_STORE_IN_AUTHZ_CODE_TABLE;
            ps1 = connection.prepareStatement(sqlQuery1);
            ps1.setString(1, newName);
            ps1.setInt(2, IdentityTenantUtil.getTenantId(tenantDomain));
            ps1.setString(3, currentName);
            ps1.executeUpdate();
            ps2 = connection.prepareStatement(sqlQuery2);
            ps2.setString(1, newName);
            ps2.setInt(2, IdentityTenantUtil.getTenantId(tenantDomain));
            ps2.setString(3, currentName);
            ps2.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error("Error occurred while renaming user store: " + currentName + " in " +
                                               "tenant :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeStatement(ps1);
            IdentityDatabaseUtil.closeStatement(ps2);
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    private AccessToken updateTokenIssuedTime(AccessToken accessToken) {

        AccessToken clonedAccessToken = new AccessToken(accessToken.getAccessToken(),
                                                        accessToken.getClientId(),
                                                        accessToken.getSubjectIdentifier(),
                                                        accessToken.getGrantType(),
                                                        accessToken.getAccessTokenState(),
                                                        new Timestamp(new Date().getTime()),
                                                        accessToken.getAccessTokenValidity());
        clonedAccessToken.setAccessTokenId(accessToken.getAccessTokenId());
        clonedAccessToken.setAuthzUser(accessToken.getAuthzUser());
        clonedAccessToken.setScopes(accessToken.getScopes());
        clonedAccessToken.setRefreshToken(accessToken.getRefreshToken());
        clonedAccessToken.setRefreshTokenIssuedTime(accessToken.getRefreshTokenIssuedTime());
        clonedAccessToken.setRefreshTokenValidity(accessToken.getRefreshTokenValidity());
        return clonedAccessToken;
    }

    private int getPoolSize() {
        String poolSizeConfig = IdentityUtil.getProperty("JDBCPersistenceManager.SessionDataPersist.PoolSize");
        if (NumberUtils.isNumber(poolSizeConfig)) {
            return Integer.parseInt(poolSizeConfig);
        }
        return 0;
    }
}
