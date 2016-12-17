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

package org.wso2.carbon.identity.inbound.auth.oauth2new.introspect;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequestFactory;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IntrospectionRequestFactory extends OAuth2IdentityRequestFactory {

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        return request.getRequestURI().contains("introspect");
    }

    @Override
    public IntrospectionRequest.IntrospectionRequestBuilder create(HttpServletRequest request,
                                                                   HttpServletResponse response) throws
                                                                                                 IntrospectionClientException {

        IntrospectionRequest.IntrospectionRequestBuilder builder = new IntrospectionRequest.IntrospectionRequestBuilder
                (request, response);
        create(builder, request, response);
        return builder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response)
            throws IntrospectionClientException {

        IntrospectionRequest.IntrospectionRequestBuilder introspectionRequestBuilder =
                (IntrospectionRequest.IntrospectionRequestBuilder)builder;
        try {
            super.create(builder, request, response);
        } catch (FrameworkClientException e) {
            throw IntrospectionClientException.error(e.getMessage(), e);
        }
        introspectionRequestBuilder.setToken(request.getParameter("token"));
        introspectionRequestBuilder.setTokenTypeHint(request.getParameter("token_type_hint"));
    }
}
