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

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class RevocationServiceImpl implements RevocationService {

    private static volatile RevocationService instance = new RevocationServiceImpl();

    private RevocationServiceImpl() {

    }

    public static RevocationService getInstance() {
        return instance;
    }

    @Override
    public Set<OAuth2App> getAppsAuthorizedByUser(AuthenticatedUser user) {

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(null);
        Set<AccessToken> accessTokens = dao.getAuthorizedAccessTokens(user, null);
        Set<OAuth2App> apps = new HashSet();
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
            // This is a performance killer. This is because service provider component doesn't provide support for
            // globally unique client IDs and IDN_OAUTH2_ACCESS_TOKEN table doesn't store tenant IDs for service
            // providers
            for(Tenant tenant:allTenants) {
                OAuth2App app = OAuth2Util.getOAuth2App(accessToken.getClientId(), tenant.getDomain());
                if(app != null) {
                    apps.add(app);
                    break;
                }
            }

        }
        return apps;
    }

    @Override
    public void revokeApplication(AuthenticatedUser user, String clientId) {

        RORevocationMessageContext messageContext = createMessageContext(user, clientId);

        HandlerManager.getInstance().triggerPreTokenRevocationsByResourceOwner(user, clientId, messageContext);

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        Set<AccessToken> accessTokens = dao.getAuthorizedAccessTokens(user, messageContext);
        for (AccessToken accessToken : accessTokens) {
            if (clientId.equals(accessToken.getClientId())) {
                dao.revokeAccessToken(accessToken.getAccessToken(), messageContext);
            }
        }

        HandlerManager.getInstance().triggerPostTokenRevocationsByResourceOwner(user, clientId, messageContext);
    }

    @Override
    public void revokeApplications(AuthenticatedUser user) {

        RORevocationMessageContext messageContext = createMessageContext(user, null);

        HandlerManager.getInstance().triggerPreTokenRevocationsByResourceOwner(user, messageContext);

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        Set<AccessToken> accessTokens = dao.getAuthorizedAccessTokens(user, messageContext);
        for (AccessToken accessToken : accessTokens) {
            dao.revokeAccessToken(accessToken.getAccessToken(), messageContext);
        }

        HandlerManager.getInstance().triggerPostTokenRevocationsByResourceOwner(user, messageContext);
    }

    private RORevocationMessageContext createMessageContext(AuthenticatedUser user, String clientId) {

        RORevocationRequest.RORevokeRequestBuilder builder = new RORevocationRequest.RORevokeRequestBuilder(user);
        builder.addClientId(clientId);
        RORevocationRequest request = builder.build();
        RORevocationMessageContext messageContext = new RORevocationMessageContext(request, new HashMap<String,String>());
        return messageContext;
    }

}
