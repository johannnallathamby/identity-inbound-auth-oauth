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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;


public class AuthzResponse extends ROApprovalResponse {

    private static final long serialVersionUID = 2602695389647693274L;

    protected OAuthASResponse.OAuthAuthorizationResponseBuilder builder;
    protected boolean isFragmentUrl;

    protected AuthzResponse(AuthzResponseBuilder builder) {
        super(builder);
        this.builder = builder.builder;
        this.isFragmentUrl = builder.isFragmentUrl;
    }

    public OAuthASResponse.OAuthAuthorizationResponseBuilder getBuilder() {
        return this.builder;
    }

    public boolean isFragmentUrl() {
        return isFragmentUrl;
    }

    public static class AuthzResponseBuilder extends ROApprovalResponseBuilder {

        protected OAuthASResponse.OAuthAuthorizationResponseBuilder builder;
        protected boolean isFragmentUrl;

        public AuthzResponseBuilder setOLTUBuilder(OAuthASResponse.OAuthAuthorizationResponseBuilder
                                                                        builder) {
            this.builder = builder;
            return this;
        }

        public AuthzResponseBuilder setFragmentUrl(boolean isFragmentUrl) {
            this.isFragmentUrl = isFragmentUrl;
            return this;
        }

        public AuthzResponseBuilder setParam(String key, String value) {
            builder.setParam(key, value);
            return this;
        }

        public AuthzResponse build() {
            return new AuthzResponse(this);
        }
    }
}
