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

package org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.clientcredentials.ClientCredentialsGrantRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

public class ClientCredentialsGrantHandler extends AuthorizationGrantHandler {

    // TODO: move this implementation to framework, remove it from here and update framework dependency version
    public String getName() {
        return this.getClass().getSimpleName();
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        TokenMessageContext tokenMessageContext = (TokenMessageContext)messageContext;
        if(GrantType.CLIENT_CREDENTIALS.toString().equals(
                ((TokenMessageContext) messageContext).getRequest().getGrantType())) {
            return true;
        }
        return false;
    }

    /**
     * Validate the authorization grant.
     *
     * @param messageContext The runtime message context
     */
    public void validateGrant(TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {

        super.validateGrant(messageContext);
        messageContext.setAuthzUser(OAuth2Util.createLocalAuthenticatedUser(
                messageContext.getApplication().getServiceProvider().getOwner(), messageContext));
        messageContext.setApprovedScopes(((ClientCredentialsGrantRequest)messageContext.getRequest()).getScopes());
    }
}
