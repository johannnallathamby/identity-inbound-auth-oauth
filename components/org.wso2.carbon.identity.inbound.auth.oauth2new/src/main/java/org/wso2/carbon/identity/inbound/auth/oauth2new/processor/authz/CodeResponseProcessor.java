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
import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.AuthzResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;

import javax.servlet.http.HttpServletResponse;
import java.sql.Timestamp;
import java.util.Date;

/*
 * InboundRequestProcessor for response_type=code
 */
public class CodeResponseProcessor extends ROApprovalProcessor {

    private OAuthIssuerImpl oltuIssuer = new OAuthIssuerImpl(new MD5Generator());

    public boolean canHandle(IdentityRequest identityRequest) {
        if(StringUtils.equals(ResponseType.CODE.toString(),
                identityRequest.getParameter(OAuth.OAUTH_RESPONSE_TYPE))) {
            return true;
        }
        return false;
    }

    protected AuthzResponse.AuthzResponseBuilder buildAuthzResponse(AuthzMessageContext messageContext) {

        Timestamp timestamp = new Timestamp(new Date().getTime());

        long authzCodeValidity = OAuth2ServerConfig.getInstance().getAuthzCodeValidity();
        long callbackValidityPeriod = messageContext.getAccessTokenValidityPeriod();
        if (callbackValidityPeriod != OAuth2.UNASSIGNED_VALIDITY_PERIOD && callbackValidityPeriod > 0) {
            authzCodeValidity = callbackValidityPeriod;
        }
        authzCodeValidity = authzCodeValidity * 1000;

        String authorizationCode = null;
        try {
            authorizationCode = oltuIssuer.authorizationCode();
        } catch (OAuthSystemException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }

        AuthzCode authzCode = new AuthzCode(authorizationCode, messageContext.getRequest().getClientId(),
                                            messageContext.getRequest().getRedirectURI(),
                                            messageContext.getAuthzUser(),
                                            timestamp, authzCodeValidity,
                                            OAuth2.TokenState.ACTIVE);
        authzCode.setScopes(messageContext.getApprovedScopes());
        authzCode.setPkceCodeChallenge(messageContext.getRequest().getPkceCodeChallenge());
        authzCode.setPkceCodeChallengeMethod(messageContext.getRequest().getPkceCodeChallengeMethod());

        HandlerManager.getInstance().getOAuth2DAO(messageContext).storeAuthzCode(authzCode, messageContext);
        messageContext.addParameter(OAuth2.AUTHZ_CODE, authzCode);

        OAuthASResponse.OAuthAuthorizationResponseBuilder oltuRespBuilder = OAuthASResponse
                .authorizationResponse(null, HttpServletResponse.SC_FOUND)
                .location(messageContext.getRequest().getRedirectURI())
                .setCode(authorizationCode)
                .setExpiresIn(Long.toString(authzCodeValidity))
                .setParam(OAuth.OAUTH_STATE, messageContext.getRequest().getState());

        AuthzResponse.AuthzResponseBuilder builder = new AuthzResponse.AuthzResponseBuilder(messageContext);
        builder.setOLTUAuthzResponseBuilder(oltuRespBuilder);
        return builder;
    }
}
