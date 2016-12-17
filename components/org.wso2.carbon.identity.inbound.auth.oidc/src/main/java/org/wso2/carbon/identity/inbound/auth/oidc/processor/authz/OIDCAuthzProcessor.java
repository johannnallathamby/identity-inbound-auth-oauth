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

package org.wso2.carbon.identity.inbound.auth.oidc.processor.authz;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz.AuthzProcessor;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.authz.OIDCAuthzRequest;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public class OIDCAuthzProcessor extends AuthzProcessor {

    public int getPriority() {
        return 0;
    }

    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    public String getRelyingPartyId() {
        return null;
    }

    public boolean canHandle(IdentityRequest identityRequest) {
        return identityRequest instanceof OIDCAuthzRequest ? true : false;
    }

    /**
     * Initiate the request to authenticate resource owner
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint
     */
    protected FrameworkLoginResponse.FrameworkLoginResponseBuilder initializeResourceOwnerAuthentication(
            AuthzMessageContext messageContext) {

        boolean isLoginRequired = ((OIDCAuthzRequest)messageContext.getRequest()).isLoginRequired();
        messageContext.addParameter(InboundConstants.ForceAuth, isLoginRequired);
        boolean isPromptNone = ((OIDCAuthzRequest)messageContext.getRequest()).isPromptNone();
        messageContext.addParameter(InboundConstants.PassiveAuth, isPromptNone);
        return super.initializeResourceOwnerAuthentication(messageContext);
    }

}
