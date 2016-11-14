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

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class HttpUserinfoResponseFactory extends HttpIdentityResponseFactory {

    public String getName() {
        return "HttpUserinfoResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        return identityResponse instanceof UserInfoResponse ? true : false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        create(builder, identityResponse);
        return builder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder,
                       IdentityResponse identityResponse) {

        httpIdentityResponseBuilder.setContentType(OAuth.ContentType.JSON);
        UserInfoResponse userInfoResponse = (UserInfoResponse)identityResponse;
        String body = userInfoResponse.getUserInfo().toJSONObject().toJSONString();
        httpIdentityResponseBuilder.setBody(body);
    }
}
