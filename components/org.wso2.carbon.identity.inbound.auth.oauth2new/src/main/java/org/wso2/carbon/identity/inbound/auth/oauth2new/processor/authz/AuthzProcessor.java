/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz;

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.OAuth2AuthzRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2InternalException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.internal.OAuth2DataHolder;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.OAuth2IdentityRequestProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

import java.util.HashMap;
import java.util.List;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public class AuthzProcessor extends OAuth2IdentityRequestProcessor {

    @Override
    public String getName() {
        return "AuthzProcessor";
    }

    public int getPriority() {
        return 0;
    }

    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    public String getRelyingPartyId() {
        return null;
    }

    public boolean canHandle(IdentityRequest identityRequest) {
        if(identityRequest.getParameter(OAuth.OAUTH_RESPONSE_TYPE) != null) {
            return true;
        }
        return false;
    }

    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest)
            throws FrameworkException {

        OAuth2AuthzMessageContext messageContext = new OAuth2AuthzMessageContext(
                (OAuth2AuthzRequest) identityRequest, new HashMap<String,String>());

        validateClient(messageContext);

        return initializeResourceOwnerAuthentication(messageContext);
    }

    protected void validateClient(OAuth2AuthzMessageContext messageContext) throws OAuth2ClientException {

        String clientId = messageContext.getRequest().getClientId();

        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = OAuth2DataHolder.getInstance().getAppMgtService()
                    .getServiceProviderByClientId(clientId, "oauth2", messageContext.getRequest().getTenantDomain());
        } catch (IdentityApplicationManagementException e) {
            throw OAuth2RuntimeException.error("Error occurred while retrieving service provider.");
        }
        if(serviceProvider == null) {
            throw OAuth2ClientException.error("Invalid Client ID: " + clientId);
        }
        // Validate clientId, redirect_uri, response_type allowed
        for(InboundAuthenticationRequestConfig config:serviceProvider.getInboundAuthenticationConfig()
                .getInboundAuthenticationRequestConfigs()) {
            if(IdentityApplicationConstants.OAuth2.NAME.equals(config.getInboundAuthType())) {
                Property[] properties = config.getProperties();
                String redirect_uri = IdentityApplicationManagementUtil.getPropertyValue(properties,
                                                                                         IdentityApplicationConstants.OAuth2.CALLBACK_URL);
                if(!messageContext.getRequest().getRedirectURI().equals(redirect_uri)) {
                    throw OAuth2ClientException.error("Invalid Redirect URI: " + redirect_uri);
                }

                List<String> responseTypes = OAuth2Util.getPropertyValuesOfPropertyNameStartsWith(properties,
                                                                                                  "response_type");
                if(!responseTypes.contains(messageContext.getRequest().getResponseType())) {
                    throw OAuth2ClientException.error("Invalid Response Type: " + messageContext.getRequest()
                            .getResponseType());
                }

            }
        }
        messageContext.addParameter(OAuth2.OAUTH2_SERVICE_PROVIDER, serviceProvider);
    }

    protected FrameworkLoginResponse.FrameworkLoginResponseBuilder initializeResourceOwnerAuthentication(
            OAuth2AuthzMessageContext messageContext) {

        return buildResponseForFrameworkLogin(messageContext);
    }

}
