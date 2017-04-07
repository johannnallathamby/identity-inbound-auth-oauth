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

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2.ClientType;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Utils;

import java.util.Arrays;

public class BasicAuthHandler extends ClientAuthHandler {

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return ((OAuth2MessageContext)messageContext).getRequest().getHeaderMap().get(OAuth.HeaderType.AUTHORIZATION)
               != null;
    }

    @Override
    public ClientType clientType(OAuth2MessageContext messageContext) {
        return ClientType.CONFIDENTIAL;
    }

    @Override
    public void authenticate(OAuth2MessageContext messageContext) throws OAuth2AuthnException {

        String authzHeader = messageContext.getRequest().getHeaderMap().get(OAuth.HeaderType.AUTHORIZATION.toLowerCase());
        //TODO: Header map keys in IdentityRequest must be case insensitive because http spec says header names are
        //TODO: case insensitive. Need to implement case insensitivity logic in getters and setters of header map.
        if(authzHeader == null) {
            authzHeader = messageContext.getRequest().getHeaderMap().get(OAuth.HeaderType.AUTHORIZATION);
        }
        String clientId = null;
        if(StringUtils.isNotBlank(authzHeader)) {
            String[] splitValues = authzHeader.trim().split(" ");
            if (splitValues.length == 2) {
                byte[] decodedBytes = Base64Utils.decode(splitValues[1].trim());
                if (ArrayUtils.isNotEmpty(decodedBytes)) {
                    String idSecret = new String(decodedBytes, Charsets.UTF_8);
                    String[] idSecretArray = idSecret.split(":");
                    if (idSecretArray.length == 2) {
                        clientId = idSecretArray[0];
                        String clientSecret = idSecretArray[1];
                        OAuth2App app = OAuth2Utils.getOAuth2App(
                                clientId, messageContext.getRequest().getTenantDomain());
                        if(app != null) {
                            if(Arrays.equals(clientSecret.toCharArray(), app.getClientSecret())){
                                messageContext.setApplication(app);
                                messageContext.setRelyingPartyID(clientId);
                                return;
                            }
                        }
                    }

                }
            }
        }
        StringBuffer message = new StringBuffer("Unauthenticated Client");
        if(StringUtils.isNotBlank(clientId)){
            message.append(" ").append(clientId);
        }
        throw OAuth2AuthnException.error(message.toString());
    }
}
