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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.authzcode;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.TokenRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthzCodeGrantFactory extends TokenRequestFactory {

    @Override
    public String getName() {
        return "AuthzCodeGrantFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(StringUtils.equals(GrantType.AUTHORIZATION_CODE.toString(), request.getParameter(OAuth.OAUTH_GRANT_TYPE))) {
            return true;
        }
        return false;
    }

    @Override
    public AuthzCodeGrantRequest.AuthzCodeGrantBuilder create(HttpServletRequest request, HttpServletResponse response)
            throws OAuth2ClientException {

        AuthzCodeGrantRequest.AuthzCodeGrantBuilder builder = new AuthzCodeGrantRequest.AuthzCodeGrantBuilder
                (request, response);
        create(builder, request, response);
        return builder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                                                              HttpServletResponse response)
            throws OAuth2ClientException {

        AuthzCodeGrantRequest.AuthzCodeGrantBuilder authzCodeGrantBuilder = (AuthzCodeGrantRequest.AuthzCodeGrantBuilder)builder;
        super.create(authzCodeGrantBuilder, request, response);
        authzCodeGrantBuilder.setCode(request.getParameter(OAuth.OAUTH_CODE));
        authzCodeGrantBuilder.setRedirectURI(request.getParameter(OAuth.OAUTH_REDIRECT_URI));
        authzCodeGrantBuilder.setPKCECodeVerifier(request.getParameter(OAuth2.PKCE_CODE_VERIFIER));
    }
}
