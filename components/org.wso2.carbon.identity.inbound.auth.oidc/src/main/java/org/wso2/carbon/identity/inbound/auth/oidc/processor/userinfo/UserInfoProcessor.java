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

package org.wso2.carbon.identity.inbound.auth.oidc.processor.userinfo;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessCoordinator;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.OAuth2IdentityRequestProcessor;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.context.UserinfoMessageContext;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.userinfo.UserInfoResponse;
import org.wso2.carbon.identity.inbound.auth.oidc.exception.AccessTokenValidationException;

import java.util.HashMap;

public class UserInfoProcessor extends OAuth2IdentityRequestProcessor {

    @Override
    public String getName() {
        return "UserInfoProcessor";
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        return identityRequest.getRequestURI().contains("/userinfo");
    }

    @Override
    public UserInfoResponse.UserInfoResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        UserinfoMessageContext messageContext = new UserinfoMessageContext(identityRequest, new HashMap());

        validateAccessToken(messageContext);

        UserInfoResponse.UserInfoResponseBuilder userInfoResponseBuilder = new UserInfoResponse
                .UserInfoResponseBuilder(messageContext);
        return userInfoResponseBuilder;
    }

    protected void validateAccessToken(UserinfoMessageContext messageContext) throws FrameworkException {

        // validate Bearer header correctly as in UserInforRequestDefaultValidator
        String accessToken = null;
        String tokenTypeHint = null;

        IntrospectionRequest.IntrospectionRequestBuilder builder = new IntrospectionRequest
                .IntrospectionRequestBuilder();
        builder.setToken(accessToken);
        builder.setTokenTypeHint(tokenTypeHint);
        // TODO: build() methods of all builders must throw client exceptions. Need API change in framework.
        IntrospectionRequest introspectionRequest = builder.build();
        messageContext.setIntrospectionRequest(introspectionRequest);
        IdentityProcessCoordinator coordinator = new IdentityProcessCoordinator();

        IntrospectionResponse response = (IntrospectionResponse) coordinator.process(introspectionRequest);
        if(!response.isActive()) {
            throw AccessTokenValidationException.error("Invalid access token.");
        } else {
            messageContext.setIntrospectionResponse(response);
        }
    }
}
