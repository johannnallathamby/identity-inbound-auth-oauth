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

package org.wso2.carbon.identity.inbound.auth.oauth2new.handler.interceptor;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RORevocationMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationMessageContext;

public abstract class OAuth2EventInterceptor extends AbstractIdentityMessageHandler {

    // TODO: move this implementation to framework, remove it from here and update framework dependency version
    public String getName() {
        return this.getClass().getSimpleName();
    }

    public void onPreTokenIssue(OAuth2MessageContext messageContext) {
        // Nothing to implement
    }

    public void onPostTokenIssue(OAuth2MessageContext messageContext) {
        // Nothing to implement
    }

    public void onPreTokenRevocationByClient(RevocationMessageContext messageContext) {
        // Nothing to implement
    }

    public void onPostTokenRevocationByClient(RevocationMessageContext messageContext) {
        // Nothing to implement
    }

    public void onPreTokenRevocationByResourceOwner(AuthenticatedUser user, RORevocationMessageContext messageContext) {
        // Nothing to implement
    }

    public void onPostTokenRevocationByResourceOwner(AuthenticatedUser user, RORevocationMessageContext messageContext)  {
        // Nothing to implement
    }

    public void onPreTokenRevocationByResourceOwner(AuthenticatedUser user, String clientId, RORevocationMessageContext messageContext) {
        // Nothing to implement
    }

    public void onPostTokenRevocationByResourceOwner(AuthenticatedUser user, String clientId, RORevocationMessageContext messageContext)  {
        // Nothing to implement
    }

    public void onPostTokenIntrospection(IntrospectionMessageContext messageContext) {
        // Nothing to implement
    }

    public void onPreTokenIntrospection(IntrospectionMessageContext messageContext) {
        // Nothing to implement
    }
}
