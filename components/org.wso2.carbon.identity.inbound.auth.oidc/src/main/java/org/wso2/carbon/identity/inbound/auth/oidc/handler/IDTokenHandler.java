/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.inbound.auth.oidc.handler;

import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oidc.IDTokenBuilder;

public class IDTokenHandler extends AbstractIdentityMessageHandler {

    @Override
    public String getName() {
        return "IDTokenHandler";
    }

    public IDTokenBuilder buildIDToken(OAuth2MessageContext messageContext) {

        if(messageContext instanceof OAuth2AuthzMessageContext) {
            return buildIDToken((OAuth2AuthzMessageContext)messageContext);
        } else {
            return buildIDToken((OAuth2TokenMessageContext)messageContext);
        }
    }

    protected IDTokenBuilder buildIDToken(OAuth2AuthzMessageContext messageContext) {

        // use IDTokenBuilder to build IDToken
        return null;
    }

    protected IDTokenBuilder buildIDToken(OAuth2TokenMessageContext messageContext) {

        // use IDTokenBuilder to build IDToken
        return null;
    }
}
