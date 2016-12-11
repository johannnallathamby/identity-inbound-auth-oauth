/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.inbound.auth.oauth2new.internal;

import org.wso2.carbon.identity.core.AbstractIdentityTenantMgtListener;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.stratos.common.exception.StratosException;

import java.util.Set;

public class OAuth2TenantMgtListener extends AbstractIdentityTenantMgtListener {

    @Override
    public void onPreDelete(int tenantId) throws StratosException {

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(null);
        Set<AccessToken> accessTokens = dao.getAccessTokensOfTenant(IdentityTenantUtil.getTenantDomain
                (tenantId), false);
        for(AccessToken accessToken:accessTokens) {
            dao.updateAccessTokenState(accessToken.getAccessToken(), OAuth2.TokenState.INACTIVE, null);
        }
        Set<AuthzCode> authzCodes = dao.getAuthorizationCodesOfTenant(IdentityTenantUtil.getTenantDomain(tenantId),
                                                                      false);
        for (AuthzCode authzCode : authzCodes) {
            dao.updateAuthzCodeState(authzCode.getAuthzCode(), OAuth2.TokenState.INACTIVE, null);
        }
    }
}
