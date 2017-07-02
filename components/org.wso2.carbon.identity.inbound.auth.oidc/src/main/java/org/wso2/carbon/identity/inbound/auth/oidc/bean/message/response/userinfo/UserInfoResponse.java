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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.userinfo;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class UserInfoResponse extends IdentityResponse {

    private static final long serialVersionUID = -2260150340336759491L;

    protected UserInfo userInfo;

    protected UserInfoResponse(UserInfoResponseBuilder builder) {
        super(builder);
        this.userInfo = builder.userInfo;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public static class UserInfoResponseBuilder extends IdentityResponseBuilder {

        protected UserInfo userInfo;

        public UserInfoResponseBuilder setUserInfo(UserInfo userInfo) {
            this.userInfo = userInfo;
            return this;
        }

        public UserInfoResponse build() {
            return new UserInfoResponse(this);
        }
    }
}
