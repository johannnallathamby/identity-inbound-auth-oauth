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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuth2IdentityRequest extends IdentityRequest {

    private static final long serialVersionUID = 5255384558894431030L;

    protected OAuth2IdentityRequest(OAuth2IdentityRequestBuilder builder) {
        super(builder);
    }

    public static class OAuth2IdentityRequestBuilder extends IdentityRequestBuilder {

        public OAuth2IdentityRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public OAuth2IdentityRequestBuilder() {

        }

        public OAuth2IdentityRequest build() {
            return new OAuth2IdentityRequest(this);
        }
    }
}
