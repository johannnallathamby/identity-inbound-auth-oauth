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
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.AccessTokenValidationException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Utils;

import javax.ws.rs.core.HttpHeaders;

public class BearerTokenFormPostHandler extends ClientAuthHandler {

    @Override
    public boolean canHandle(MessageContext messageContext) {
        String token = ((OAuth2MessageContext)messageContext).getRequest().getParameter(OAuth.OAUTH_ACCESS_TOKEN);
        if (StringUtils.isNotBlank(token)) {
            return true;
        }
        return false;
    }

    @Override
    public OAuth2.ClientType clientType(OAuth2MessageContext messageContext) {
        //TODO: need to fix this
        return OAuth2.ClientType.CONFIDENTIAL;
    }

    @Override
    public void authenticate(OAuth2MessageContext messageContext) throws OAuth2AuthnException {

        String contentTypeHeaders = messageContext.getRequest().getHeader(HttpHeaders.CONTENT_TYPE);
        if (StringUtils.isEmpty(contentTypeHeaders)) {
            throw AccessTokenValidationException.error("Content-Type header is missing.");
        }
        String body = messageContext.getRequest().getBody();
        if (!(OAuth.ContentType.URL_ENCODED).equals(contentTypeHeaders.trim())) {
            throw AccessTokenValidationException.error("Content-Type header is wrong.");
        }
        if (!OAuth2Utils.isPureAscii(body)) {
            throw AccessTokenValidationException.error("Body contains non ASCII characters");
        }
        String[] accessTokens = messageContext.getRequest().getParameterValues("access_token");
        if (accessTokens.length > 1) {
            throw AccessTokenValidationException.error("Request contains more than one " + OAuth.ContentType
                    .URL_ENCODED + "access tokens.");
        }
        AccessToken accessToken = OAuth2Utils.validateAccessToken(accessTokens[0]);
        messageContext.addParameter(OAuth2.ACCESS_TOKEN, accessToken);
        messageContext.setApplication(OAuth2Utils.getOAuth2App(accessToken.getClientId()));
    }
}
