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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthzApprovedRequestFactory extends OAuth2IdentityRequestFactory {

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        return StringUtils.isNotBlank(request.getParameter(OAuth2.CONSENT));
    }

    @Override
    public AuthzApprovedRequest.AuthzApprovedRequestBuilder create(HttpServletRequest request,
                                                                   HttpServletResponse response) throws OAuth2ClientException {

        AuthzApprovedRequest.AuthzApprovedRequestBuilder builder = new AuthzApprovedRequest.AuthzApprovedRequestBuilder
                (request, response);
        create(builder, request, response);
        return builder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response) throws OAuth2ClientException {

        AuthzApprovedRequest.AuthzApprovedRequestBuilder authzApprovedRequestBuilder =
                (AuthzApprovedRequest.AuthzApprovedRequestBuilder)builder;
        try {
            super.create(authzApprovedRequestBuilder, request, response);
        } catch (FrameworkClientException e) {
            throw OAuth2ClientException.error(e.getMessage(), e);
        }
        authzApprovedRequestBuilder.setSessionDataKey(request.getParameter(
                InboundConstants.RequestProcessor.CONTEXT_KEY));
        authzApprovedRequestBuilder.setConsent(request.getParameter(OAuth2.CONSENT));
    }
}