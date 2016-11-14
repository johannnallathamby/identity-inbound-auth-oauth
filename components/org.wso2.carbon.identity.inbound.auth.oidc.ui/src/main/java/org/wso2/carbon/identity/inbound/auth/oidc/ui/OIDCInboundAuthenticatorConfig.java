/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.inbound.auth.oidc.ui;

import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;

public class OIDCInboundAuthenticatorConfig extends AbstractInboundAuthenticatorConfig {

    @Override
    public String getName() {
        return IdentityApplicationConstants.OAuth2.NAME;
    }

    @Override
    public String getConfigName() {
        return IdentityApplicationConstants.OAuth2.NAME;
    }

    @Override
    public String getFriendlyName() {
        return "OAuth2/OIDC Inbound Configuration";
    }

    @Override
    public Property[] getConfigurationProperties() {

        Property[] configProperties = new Property[7];

        Property clientId = new Property();
        clientId.setName(IdentityApplicationConstants.OAuth2.CLIENT_ID);
        clientId.setDescription("OAuth2 Client ID of the service provider");
        clientId.setDisplayName("Client Id");
        clientId.setDisplayOrder(1);
        clientId.setAdvanced(false);
        clientId.setConfidential(false);
        clientId.setRequired(true);
        configProperties[0] = clientId;

        Property clientSecret = new Property();
        clientSecret.setName(IdentityApplicationConstants.OAuth2.CLIENT_SECRET);
        clientSecret.setDescription("OAuth2/OpenID Connect Client Secret of the service provider");
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setDisplayOrder(2);
        clientSecret.setAdvanced(false);
        clientSecret.setConfidential(true);
        clientSecret.setRequired(true);
        configProperties[1] = clientSecret;

        Property redirectURI = new Property();
        redirectURI.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        redirectURI.setDescription("OAuth2/OpenID Connect Redirect URI of the service provider.");
        redirectURI.setDisplayName("Redirect URI");
        redirectURI.setDisplayOrder(3);
        redirectURI.setAdvanced(false);
        redirectURI.setConfidential(false);
        redirectURI.setRequired(false);
        configProperties[2] = redirectURI;

        Property allowedGrantTypes = new Property();
        allowedGrantTypes.setName("allowed_grant_types");
        allowedGrantTypes.setDescription("OAuth2/OpenID Connect Grant types allowed for this service provider.");
        allowedGrantTypes.setDisplayName("Allowed Grant Types");
        allowedGrantTypes.setDisplayOrder(4);
        allowedGrantTypes.setAdvanced(false);
        allowedGrantTypes.setConfidential(false);
        allowedGrantTypes.setRequired(true);
        allowedGrantTypes.setDefaultValue("all");
        allowedGrantTypes.setValue("all");
        configProperties[3] = allowedGrantTypes;

        Property allowedResponseTypes = new Property();
        allowedResponseTypes.setName("allowed_response_types");
        allowedResponseTypes.setDescription("OAuth2/OpenID Connect Response types allowed for this service provider.");
        allowedResponseTypes.setDisplayName("Allowed Response Types");
        allowedResponseTypes.setDisplayOrder(5);
        allowedResponseTypes.setAdvanced(false);
        allowedResponseTypes.setConfidential(false);
        allowedResponseTypes.setRequired(true);
        allowedResponseTypes.setDefaultValue("all");
        allowedResponseTypes.setValue("all");
        configProperties[4] = allowedResponseTypes;

        Property pkceMandatory = new Property();
        pkceMandatory.setName("pkce_mandatory");
        pkceMandatory.setDescription("Only allow applications that bear PKCE Code Challenge with them.");
        pkceMandatory.setDisplayName("PKCE Mandatory");
        pkceMandatory.setDisplayOrder(6);
        pkceMandatory.setAdvanced(false);
        pkceMandatory.setConfidential(false);
        pkceMandatory.setRequired(false);
        pkceMandatory.setDefaultValue("false");
        pkceMandatory.setValue("false");
        configProperties[5] = pkceMandatory;

        Property pkcePlainAllowed = new Property();
        pkcePlainAllowed.setName("pkce_plain_allowed");
        pkcePlainAllowed.setDescription("Server supports 'S256' PKCE tranformation algorithm by default.");
        pkcePlainAllowed.setDisplayName("Support PKCE 'Plain' Transform Algorithm");
        pkcePlainAllowed.setDisplayOrder(7);
        pkcePlainAllowed.setAdvanced(false);
        pkcePlainAllowed.setConfidential(false);
        pkcePlainAllowed.setRequired(false);
        pkcePlainAllowed.setDefaultValue("false");
        pkcePlainAllowed.setValue("false");
        configProperties[6] = pkcePlainAllowed;

        return configProperties;
    }

    public String getRelyingPartyKey() {
        return IdentityApplicationConstants.OAuth2.CLIENT_ID;
    }
}
