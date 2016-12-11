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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;

import java.util.HashSet;
import java.util.Set;

public class OAuth2ApplicationMgtListener extends AbstractApplicationMgtListener {


    @Override
    public int getDefaultOrderId() {
        return 11;
    }


    public boolean doPreUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {

        inactiveTokens(serviceProvider);
        return true;
    }

    @Override
    public boolean doPreDeleteApplication(String applicationName, String tenantDomain, String userName) throws IdentityApplicationManagementException {

        ApplicationManagementService applicationMgtService = OAuth2DataHolder.getInstance().getAppMgtService();
        ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(applicationName, tenantDomain);
        inactiveTokens(serviceProvider);
        return true;
    }

    private void inactiveTokens(ServiceProvider serviceProvider) throws IdentityApplicationManagementException {

        Set<AccessToken> accessTokens = new HashSet<>();
        Set<AuthzCode> authzCodes = new HashSet<>();
        String clientId = null;

        InboundAuthenticationConfig inboundAuthenticationConfig = serviceProvider.getInboundAuthenticationConfig();
        if (inboundAuthenticationConfig != null) {
            InboundAuthenticationRequestConfig[] inboundRequestConfigs = inboundAuthenticationConfig.
                    getInboundAuthenticationRequestConfigs();
            if (inboundRequestConfigs != null) {
                for (InboundAuthenticationRequestConfig inboundRequestConfig : inboundRequestConfigs) {
                    if (StringUtils.equals(IdentityApplicationConstants.OAuth2.NAME, inboundRequestConfig
                            .getInboundAuthType())) {
                        clientId = inboundRequestConfig.getInboundAuthKey();
                        accessTokens = HandlerManager.getInstance().getOAuth2DAO(null)
                                .getAccessTokensByClientId(clientId, false);
                        authzCodes = HandlerManager.getInstance().getOAuth2DAO(null)
                                .getAuthorizationCodesByClientId(clientId, false);
                    }
                }
            }
        }
        for (AccessToken accessToken : accessTokens) {
            HandlerManager.getInstance().getOAuth2DAO(null).updateAccessTokenState(accessToken.getAccessToken(), OAuth2.TokenState
                    .INACTIVE, null);
        }
        for (AuthzCode authzCode : authzCodes) {
            HandlerManager.getInstance().getOAuth2DAO(null).updateAuthzCodeState(authzCode.getAuthzCode(), OAuth2.TokenState
                    .INACTIVE, null);
        }
    }
}