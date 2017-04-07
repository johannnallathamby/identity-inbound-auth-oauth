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

package org.wso2.carbon.identity.inbound.auth.oauth2new.handler.client;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Utils;

import java.util.Arrays;

public class FormPostHandler extends ClientAuthHandler {

    @Override
    public boolean canHandle(MessageContext messageContext) {
        OAuth2MessageContext oAuth2MessageContext = (OAuth2MessageContext)messageContext;
        String clientId = oAuth2MessageContext.getRequest().getParameter(OAuth.OAUTH_CLIENT_ID);
        String clientSecret = oAuth2MessageContext.getRequest().getParameter(OAuth.OAUTH_CLIENT_ID);
        return StringUtils.isNotBlank(clientId) && StringUtils.isNotBlank(clientSecret);
    }

    @Override
    public OAuth2.ClientType clientType(OAuth2MessageContext messageContext) {
        return OAuth2.ClientType.CONFIDENTIAL;
    }

    @Override
    public void authenticate(OAuth2MessageContext messageContext) throws OAuth2AuthnException {

        String clientId = messageContext.getRequest().getParameter(OAuth.OAUTH_CLIENT_ID);
        String clientSecret = messageContext.getRequest().getParameter(OAuth.OAUTH_CLIENT_SECRET);
        OAuth2App app = OAuth2Utils.getOAuth2App(clientId, messageContext.getRequest().getTenantDomain());
        if(app != null) {
            if(Arrays.equals(clientSecret.toCharArray(), app.getClientSecret())){
                messageContext.setApplication(app);
                messageContext.setRelyingPartyID(clientId);
                return;
            }
        }
        StringBuffer message = new StringBuffer("Unauthenticated Client");
        if(StringUtils.isNotBlank(clientId)){
            message.append(" ").append(clientId);
        }
        throw OAuth2AuthnException.error(message.toString());
    }
}
