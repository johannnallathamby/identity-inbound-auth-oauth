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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.userinfo;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserInfoRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = -1555222725037366929L;

    protected String accessToken;

    protected UserInfoRequest(UserInfoRequestBuilder builder) throws FrameworkClientException {
        super(builder);
        this.accessToken = builder.accessToken;
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    public static class UserInfoRequestBuilder extends OAuth2IdentityRequestBuilder {

        protected String accessToken;

        protected UserInfoRequestBuilder(HttpServletRequest request, HttpServletResponse response) throws
                                                                                           FrameworkClientException {
            super(request, response);
        }

        public UserInfoRequestBuilder setAccessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public UserInfoRequest build() throws FrameworkClientException {
            return new UserInfoRequest(this);
        }
    }
}
