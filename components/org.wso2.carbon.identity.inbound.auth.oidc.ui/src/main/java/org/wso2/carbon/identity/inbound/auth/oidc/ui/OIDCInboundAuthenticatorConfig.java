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

/**
 * OIDC UI AuthenticatorConfig
 */
public class OIDCInboundAuthenticatorConfig extends AbstractInboundAuthenticatorConfig {

    @Override
    public String getName() {
        return "test";
    }

    @Override
    public String getConfigName() {
        return "test";
    }

    @Override
    public String getFriendlyName() {
        return "OAuth2/OpenID Connect Inbound Configuration";
    }

    @Override
    public Property[] getConfigurationProperties() {

        Property[] configProperties = new Property[15];

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

        Property supportedGrantType1 = new Property();
        supportedGrantType1.setName("supported_grant_type.1");
        supportedGrantType1.setDisplayName("authorization_code");
        supportedGrantType1.setDisplayOrder(4);
        supportedGrantType1.setType("checkbox");
        supportedGrantType1.setRequired(false);
        configProperties[3] = supportedGrantType1;

        Property supportedGrantType2 = new Property();
        supportedGrantType2.setName("supported_grant_type.2");
        supportedGrantType2.setDisplayName("password");
        supportedGrantType2.setDisplayOrder(5);
        supportedGrantType2.setType("checkbox");
        supportedGrantType2.setRequired(false);
        configProperties[4] = supportedGrantType2;

        Property supportedGrantType3 = new Property();
        supportedGrantType3.setName("supported_grant_type.3");
        supportedGrantType3.setDisplayName("client_credentials");
        supportedGrantType3.setDisplayOrder(6);
        supportedGrantType3.setType("checkbox");
        supportedGrantType3.setRequired(false);
        configProperties[5] = supportedGrantType3;

        Property supportedGrantType4 = new Property();
        supportedGrantType4.setName("supported_grant_type.4");
        supportedGrantType4.setDisplayName("refresh_token");
        supportedGrantType4.setDisplayOrder(7);
        supportedGrantType4.setType("checkbox");
        supportedGrantType4.setRequired(false);
        configProperties[6] = supportedGrantType4;

        Property supportedGrantType5 = new Property();
        supportedGrantType5.setName("supported_grant_type.5");
        supportedGrantType5.setDisplayName("urn:ietf:params:oauth:grant-type:saml2-bearer");
        supportedGrantType5.setDisplayOrder(8);
        supportedGrantType5.setType("checkbox");
        supportedGrantType5.setRequired(false);
        configProperties[7] = supportedGrantType5;

        Property supportedResponseType1 = new Property();
        supportedResponseType1.setName("supported_response_type.1");
        supportedResponseType1.setDisplayName("code");
        supportedResponseType1.setDisplayOrder(9);
        supportedResponseType1.setType("checkbox");
        supportedResponseType1.setRequired(false);
        configProperties[8] = supportedResponseType1;

        Property supportedResponseType2 = new Property();
        supportedResponseType2.setName("supported_response_type.2");
        supportedResponseType2.setDisplayName("token");
        supportedResponseType2.setDisplayOrder(10);
        supportedResponseType2.setType("checkbox");
        supportedResponseType2.setRequired(false);
        configProperties[9] = supportedResponseType2;

        Property supportedResponseType3 = new Property();
        supportedResponseType3.setName("supported_response_type.3");
        supportedResponseType3.setDisplayName("id_token token");
        supportedResponseType3.setDisplayOrder(11);
        supportedResponseType3.setType("checkbox");
        supportedResponseType3.setRequired(false);
        configProperties[10] = supportedResponseType3;

        Property supportedResponseType4 = new Property();
        supportedResponseType4.setName("supported_response_type.4");
        supportedResponseType4.setDisplayName("id_token");
        supportedResponseType4.setType("checkbox");
        supportedResponseType4.setDisplayOrder(12);
        supportedResponseType4.setRequired(false);
        configProperties[11] = supportedResponseType4;

        Property pkceMandatory = new Property();
        pkceMandatory.setName("pkce_mandatory");
        pkceMandatory.setDescription("Only allow applications that bear PKCE Code Challenge with them.");
        pkceMandatory.setDisplayName("PKCE Mandatory");
        pkceMandatory.setDisplayOrder(13);
        pkceMandatory.setType("checkbox");
        configProperties[12] = pkceMandatory;

        Property pkcePlainAllowed = new Property();
        pkcePlainAllowed.setName("pkce_plain_allowed");
        pkcePlainAllowed.setDescription("Server supports 'S256' PKCE tranformation algorithm by default.");
        pkcePlainAllowed.setDisplayName("Support PKCE 'Plain' Transform Algorithm");
        pkcePlainAllowed.setDisplayOrder(14);
        pkcePlainAllowed.setType("checkbox");
        configProperties[13] = pkcePlainAllowed;

        Property clientSecretState = new Property();
        clientSecretState.setName("client_secret_state");
        clientSecretState.setDisplayOrder(15);
        clientSecretState.setType("hidden");
        clientSecretState.setDefaultValue("ACTIVE");
        clientSecretState.setValue("ACTIVE");
        configProperties[14] = clientSecretState;

        return configProperties;
    }

    public String getRelyingPartyKey() {
        return IdentityApplicationConstants.OAuth2.CLIENT_ID;
    }
}
