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

package org.wso2.carbon.identity.inbound.auth.oidc.userinfo;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserInfoRequestFactory extends OAuth2IdentityRequestFactory {

    @Override
    public String getName() {
        return "UserInfoRequestFactory";
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        return false;
    }

    @Override
    public UserInfoRequest.UserInfoRequestBuilder create(HttpServletRequest request,
                                                         HttpServletResponse response) throws OAuth2ClientException {
        return null;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response)
            throws OAuth2ClientException {
    }
}
