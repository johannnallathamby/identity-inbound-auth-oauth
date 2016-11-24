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

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.context.UserinfoMessageContext;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.AuthnResultCache;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.AuthnResultCacheAccessTokenKey;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.AuthnResultCacheEntry;

import java.util.HashMap;
import java.util.Map;

public class UserInfoResponse extends IdentityResponse {

    protected UserInfo userInfo;

    protected UserInfoResponse(UserInfoResponseBuilder builder) {
        super(builder);
        UserinfoMessageContext messageContext = (UserinfoMessageContext) context;
        this.userInfo = new UserInfo(new Subject(messageContext.getIntrospectionResponse().getSub()));
        this.userInfo.setClaim(OIDC.USERNAME, messageContext.getIntrospectionResponse()
                .getUsername());
        fillUserClaims(userInfo, messageContext);
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public static class UserInfoResponseBuilder extends IdentityResponseBuilder {

        public UserInfoResponseBuilder(UserinfoMessageContext messageContext) {
            super(messageContext);
        }

        public UserInfoResponse build() {
            return new UserInfoResponse(this);
        }
    }

    protected void fillUserClaims(UserInfo userInfo, UserinfoMessageContext messageContext) {

        String bearerToken = messageContext.getIntrospectionRequest().getToken();
        AccessToken accessToken = HandlerManager.getInstance().getOAuth2DAO(null).getAccessToken(bearerToken, null);
        AuthnResultCacheAccessTokenKey cacheKey = new AuthnResultCacheAccessTokenKey(accessToken.getAccessTokenId(),
                                                                                     accessToken.getAccessToken());
        AuthnResultCacheEntry cacheEntry = AuthnResultCache.getInstance().getValueFromCache(cacheKey);
        if (cacheEntry != null) {
            HashMap<ClaimMapping,String> userAttributes = (HashMap<ClaimMapping, String>) cacheEntry.getAuthnResult().getSubject()
                    .getUserAttributes();
            if(userAttributes != null) {
                for(Map.Entry<ClaimMapping,String> entry : userAttributes.entrySet()) {
                    userInfo.setClaim(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
                }
            }
        }
    }
}
