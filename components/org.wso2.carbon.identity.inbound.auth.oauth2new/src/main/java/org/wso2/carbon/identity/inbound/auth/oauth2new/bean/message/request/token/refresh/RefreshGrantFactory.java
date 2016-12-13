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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.refresh;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.TokenRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RefreshGrantFactory extends TokenRequestFactory {

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(StringUtils.equals(GrantType.REFRESH_TOKEN.toString(), request.getParameter(OAuth.OAUTH_GRANT_TYPE))) {
            return true;
        }
        return false;
    }

    @Override
    public RefreshGrantRequest.RefreshGrantBuilder create(HttpServletRequest request,
                                                          HttpServletResponse response) throws OAuth2ClientException {

        RefreshGrantRequest.RefreshGrantBuilder builder = new RefreshGrantRequest.RefreshGrantBuilder
                (request, response);
        create(builder, request, response);
        return builder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response)
            throws OAuth2ClientException {

        RefreshGrantRequest.RefreshGrantBuilder refreshGrantBuilder = (RefreshGrantRequest.RefreshGrantBuilder)builder;
        try {
            super.create(refreshGrantBuilder, request, response);
        } catch (OAuth2ClientException e) {
            throw OAuth2ClientException.error(e.getMessage(), e);
        }
        refreshGrantBuilder.setRefreshToken(request.getParameter(OAuth.OAUTH_REFRESH_TOKEN));
        refreshGrantBuilder.setScopes(OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE)));
    }
}
