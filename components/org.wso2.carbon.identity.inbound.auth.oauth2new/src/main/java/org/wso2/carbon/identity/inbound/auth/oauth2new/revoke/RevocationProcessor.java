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

package org.wso2.carbon.identity.inbound.auth.oauth2new.revoke;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2.ClientType;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.OAuth2IdentityRequestProcessor;

import java.util.HashMap;

public class RevocationProcessor extends OAuth2IdentityRequestProcessor {

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        return identityRequest instanceof RevocationRequest ? true: false;
    }

    @Override
    public RevocationResponse.RevocationResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        RevocationRequest revocationRequest = (RevocationRequest) identityRequest;
        RevocationMessageContext messageContext = new RevocationMessageContext(revocationRequest,
                new HashMap<String,String>());


        HandlerManager.getInstance().triggerPreTokenRevocationsByClient(messageContext);

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            authenticateClient(messageContext);
        }

        String token = revocationRequest.getToken();
        String tokenTypeHint = revocationRequest.getTokenTypeHint();
        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        boolean refreshTokenFirst = GrantType.REFRESH_TOKEN.toString().equals(tokenTypeHint);
        AccessToken accessToken = null;
        if (refreshTokenFirst) {
            accessToken = dao.getLatestAccessTokenByRefreshToken(token, messageContext);
            if(accessToken != null) {
                dao.revokeRefreshToken(token, messageContext);
                messageContext.addParameter("RevokedAccessToken", accessToken);
            } else {
                accessToken = dao.getAccessToken(token, messageContext);
                if(accessToken != null) {
                    dao.revokeAccessToken(accessToken.getAccessToken(), messageContext);
                    messageContext.addParameter("RevokedAccessToken", accessToken);
                }
            }
        } else {
            accessToken = dao.getAccessToken(token, messageContext);
            if (accessToken != null) {
                dao.revokeAccessToken(token, messageContext);
                messageContext.addParameter("RevokedAccessToken", accessToken);
            } else {
                accessToken = dao.getLatestAccessTokenByRefreshToken(token, messageContext);
                if(accessToken != null) {
                    dao.revokeRefreshToken(token, messageContext);
                    messageContext.addParameter("RevokedAccessToken", accessToken);
                }
            }
        }

        RevocationResponse.RevocationResponseBuilder responseBuilder = new RevocationResponse
                .RevocationResponseBuilder(messageContext);
        responseBuilder.setCallback(revocationRequest.getCallback());

        HandlerManager.getInstance().triggerPostTokenRevocationsByClient(messageContext);

        return responseBuilder;
    }

    /**
     * Finds out the client type
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected ClientType clientType(RevocationMessageContext messageContext) {
        return HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException
     */
    protected void authenticateClient(RevocationMessageContext messageContext) throws OAuth2ClientException {
        HandlerManager.getInstance().authenticateClient(messageContext);
    }
}
