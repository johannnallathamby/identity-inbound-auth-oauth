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

package org.wso2.carbon.identity.inbound.auth.oauth2new.revoke;

import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2InternalException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.internal.OAuth2DataHolder;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.HashSet;
import java.util.Set;

public class OAuth2TokenRevocationServiceImpl implements OAuth2TokenRevocationService {

    private static volatile OAuth2TokenRevocationService instance = new OAuth2TokenRevocationServiceImpl();

    private OAuth2TokenRevocationServiceImpl() {

    }

    public static OAuth2TokenRevocationService getInstance() {
        return instance;
    }

    @Override
    public Set<ServiceProvider> getAppsAuthorizedByUser(AuthenticatedUser user) throws OAuth2InternalException {

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(null);
        Set<AccessToken> accessTokens = dao.getAuthorizedAccessTokens(user, null);
        Set<ServiceProvider> serviceProviders = new HashSet();
        Tenant[] allTenants = null;
        try {
            allTenants = IdentityTenantUtil.getRealmService().getTenantManager().getAllTenants();
            if(allTenants == null) {
                allTenants = new Tenant[0];
            }
        } catch (UserStoreException e) {
            throw OAuth2RuntimeException.error("Error occurred while retrieving all tenants in the system");
        }
        for(AccessToken accessToken:accessTokens) {
            ServiceProvider serviceProvider = null;
            // This is a performance killer. This is because service provider component doesn't provide support for
            // globally unique client IDs and IDN_OAUTH2_ACCESS_TOKEN table doesn't store tenant IDs for service
            // providers
            for(Tenant tenant:allTenants) {
                try {
                    serviceProvider = OAuth2DataHolder.getInstance().getAppMgtService().getServiceProviderByClientId
                            (accessToken.getClientId(), IdentityApplicationConstants.OAuth2.NAME, tenant.getDomain());
                    if(serviceProvider != null) {
                        serviceProviders.add(serviceProvider);
                        break;
                    }
                } catch (IdentityApplicationManagementException e) {
                    throw OAuth2RuntimeException.error("Error occurred while retrieving service provider for " +
                                                       accessToken.getClientId() + " in tenant " + tenant.getDomain());
                }
            }

        }
        return serviceProviders;
    }

    @Override
    public void revokeApplication(AuthenticatedUser user, String clientId) throws OAuth2InternalException {

        HandlerManager.getInstance().triggerPreTokenRevocationsByResourceOwner(user, clientId);

        // TODO: implement method

        HandlerManager.getInstance().triggerPostTokenRevocationsByResourceOwner(user, clientId);
    }

    @Override
    public void revokeApplications(AuthenticatedUser user) throws OAuth2InternalException {

        HandlerManager.getInstance().triggerPreTokenRevocationsByResourceOwner(user);

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(null);
        Set<AccessToken> accessTokens = dao.getAuthorizedAccessTokens(user, null);
        for (AccessToken accessToken : accessTokens) {
            dao.revokeAccessToken(accessToken.getAccessToken(), null);
        }

        HandlerManager.getInstance().triggerPostTokenRevocationsByResourceOwner(user);
    }

}
