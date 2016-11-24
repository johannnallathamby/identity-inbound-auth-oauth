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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2InternalException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.UserConsent;

public class UserConsentDAO {

    private static volatile UserConsentDAO instance = new UserConsentDAO();

    private UserConsentDAO() {
    }

    public static UserConsentDAO getInstance() {
        return instance;
    }

    public void approveAppAlways(UserConsent userConsent, String appName) throws OAuth2InternalException {

        if(userConsent == null){
            throw new IllegalArgumentException("UserConsent is NULL");
        }
        UserConsent existingConsent = this.getUserConsent(userConsent.getAuthzUser(), userConsent.getApplicationId());
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            if(existingConsent != null) {
                prepStmt = connection.prepareStatement("UPDATE IDN_OAUTH2_USER_CONSENT SET TRUSTED_ALWAYS = ? WHERE " +
                                                       "USER_NAME = ? AND USER_DOMAIN = ? AND TENANT_ID = ? AND " +
                                                       "APPLICATION_ID = ?");
                prepStmt.setString(1, userConsent.isTrustedAlways()?"1":"0");
                prepStmt.setString(2, userConsent.getAuthzUser().getUserName());
                prepStmt.setString(3, userConsent.getAuthzUser().getUserStoreDomain());
                prepStmt.setInt(4, IdentityTenantUtil.getTenantId(userConsent.getAuthzUser().getTenantDomain()));
                prepStmt.setInt(5, userConsent.getApplicationId());
                prepStmt.execute();
                connection.commit();
            } else {
                prepStmt = connection.prepareStatement("INSERT INTO IDN_OAUTH2_USER_CONSENT (TRUSTED_ALWAYS, " +
                                                       "USER_NAME, USER_DOMAIN, TENANT_ID, APPLICATION_ID)" +
                                                       "VALUES (?,?,?,?,?)");
                prepStmt.setString(1, userConsent.isTrustedAlways()?"1":"0");
                prepStmt.setString(2, userConsent.getAuthzUser().getUserName());
                prepStmt.setString(3, userConsent.getAuthzUser().getUserStoreDomain());
                prepStmt.setInt(4, IdentityTenantUtil.getTenantId(userConsent.getAuthzUser().getTenantDomain()));
                prepStmt.setInt(5, userConsent.getApplicationId());
                prepStmt.execute();
                connection.commit();
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2InternalException.error("Failed to store consent for user: " + userConsent.getAuthzUser() + "" +
                                                " for application " + appName);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
            IdentityDatabaseUtil.closeConnection(connection);
        }

    }

    public UserConsent getUserConsent(AuthenticatedUser authzUser, int applicationId) throws OAuth2InternalException {

        if(authzUser == null){
            throw new IllegalArgumentException("AuthenticatedUser is NULL");
        }
        UserConsent userConsent = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement("SELECT TRUSTED_ALWAYS, FROM IDN_OAUTH2_USER_CONSENT WHERE " +
                                                   "USER_NAME = ? AND USER_DOMAIN = ? AND TENANT_ID = ? AND" +
                                                   "APPLICATION_ID = ?");
            prepStmt.setString(1, authzUser.getUserName());
            prepStmt.setString(2, authzUser.getUserStoreDomain());
            prepStmt.setInt(3, IdentityTenantUtil.getTenantId(authzUser.getTenantDomain()));
            prepStmt.setInt(4, applicationId);
            ResultSet rs = prepStmt.executeQuery();
            boolean isTrustedAlways = false;
            if(rs.next()) {
                isTrustedAlways = "1".equals(rs.getString(1)) ? true : false;
            }
            userConsent = new UserConsent(authzUser, applicationId, isTrustedAlways);
            connection.commit();
            return userConsent;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2InternalException.error("Failed to load consent for user: " + authzUser  +
                                                " for application " + applicationId);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }
}
