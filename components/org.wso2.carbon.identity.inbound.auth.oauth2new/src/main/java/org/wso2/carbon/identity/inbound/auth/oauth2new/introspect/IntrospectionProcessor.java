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

package org.wso2.carbon.identity.inbound.auth.oauth2new.introspect;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2.ClientType;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.OAuth2IdentityRequestProcessor;

import java.util.HashMap;

public class IntrospectionProcessor extends OAuth2IdentityRequestProcessor {

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        return identityRequest instanceof IntrospectionRequest;
    }

    @Override
    public IntrospectionResponse.IntrospectionResponseBuilder process(IdentityRequest identityRequest)
            throws FrameworkException {

        IntrospectionRequest introspectionRequest = (IntrospectionRequest) identityRequest;
        IntrospectionMessageContext messageContext = new IntrospectionMessageContext(introspectionRequest,
                new HashMap<String,String>());

        HandlerManager.getInstance().triggerPreTokenIntrospections(messageContext);

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            authenticateClient(messageContext);
        }

        IntrospectionResponse.IntrospectionResponseBuilder introspectionResponseBuilder = introspect(messageContext);

        HandlerManager.getInstance().triggerPostTokenIntrospections(messageContext);

        return introspectionResponseBuilder;
    }

    protected IntrospectionResponse.IntrospectionResponseBuilder introspect(IntrospectionMessageContext messageContext)
            throws OAuth2ClientException, OAuth2Exception {
        IntrospectionHandler handler = HandlerManager.getInstance().getIntrospectionHandler(messageContext);
        return handler.introspect(messageContext);
    }

    /**
     * Finds out the client type
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected ClientType clientType(IntrospectionMessageContext messageContext) {
        return HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @throws OAuth2ClientException if the client was not authenticated successfully
     */
    protected void authenticateClient(IntrospectionMessageContext messageContext) throws OAuth2AuthnException {
        HandlerManager.getInstance().authenticateClient(messageContext);
    }
}