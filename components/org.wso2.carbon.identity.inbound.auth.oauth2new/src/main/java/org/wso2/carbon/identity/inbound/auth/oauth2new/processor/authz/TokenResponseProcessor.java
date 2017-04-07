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

package org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.AuthzResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.DummyHttpServletRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Utils;

import javax.servlet.http.HttpServletResponse;

/*
 * IdentityProcessor for OIDC Authentication Endpoint with "response_type=token"
 */
public class TokenResponseProcessor extends ROApprovalProcessor {

    public boolean canHandle(IdentityRequest identityRequest) {
        if(super.canHandle(identityRequest)) {
            IdentityRequest originalClientRequest = getContextIfAvailable(identityRequest).getRequest();
            if (StringUtils.equals(ResponseType.TOKEN.toString(),
                                   originalClientRequest.getParameter(OAuth.OAUTH_RESPONSE_TYPE))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Issues the authorization endpoint response
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint response
     */
    protected AuthzResponse.AuthzResponseBuilder buildAuthzResponse(AuthzMessageContext messageContext) {

        AccessToken accessToken = issueAccessToken(messageContext);

        long expiry = 0;
        if(accessToken.getAccessTokenValidity() > 0) {
            expiry = accessToken.getAccessTokenValidity()/1000;
        } else {
            expiry = Long.MAX_VALUE/1000;
        }

        String state = messageContext.getRequest().getState();

        OAuthASResponse.OAuthAuthorizationResponseBuilder oltuRespBuilder = OAuthASResponse
                .authorizationResponse(new DummyHttpServletRequest(), HttpServletResponse.SC_FOUND)
                .location(messageContext.getRequest().getRedirectURI())
                .setAccessToken(accessToken.getAccessToken())
                .setExpiresIn(Long.toString(expiry))
                .setParam(OAuth.OAUTH_TOKEN_TYPE, OAuth.OAUTH_HEADER_NAME)
                .setParam(OAuth.OAUTH_STATE, state)
                .setParam(OAuth.OAUTH_SCOPE, OAuth2Utils.buildScopeString(accessToken.getScopes()));


        if(issueRefreshToken(messageContext)) {
            oltuRespBuilder.setParam(OAuth.OAUTH_REFRESH_TOKEN, new String(accessToken.getRefreshToken()));
        }
        
        AuthzResponse.AuthzResponseBuilder builder = new AuthzResponse.AuthzResponseBuilder(messageContext);
        builder.setOLTUAuthzResponseBuilder(oltuRespBuilder);
        builder.setFragmentUrl(true);
        return builder;
    }

    /**
     * Issues the access token
     *
     * @param messageContext The runtime message context
     * @return OAuth2 access token response
     * @throws OAuth2Exception
     */
    protected AccessToken issueAccessToken(AuthzMessageContext messageContext) {
        AccessToken accessToken = HandlerManager.getInstance().issueAccessToken(messageContext);
        messageContext.addParameter(OAuth2.ACCESS_TOKEN, accessToken);
        return accessToken;
    }

    protected boolean issueRefreshToken(AuthzMessageContext messageContext) {
        return false;
    }

}
