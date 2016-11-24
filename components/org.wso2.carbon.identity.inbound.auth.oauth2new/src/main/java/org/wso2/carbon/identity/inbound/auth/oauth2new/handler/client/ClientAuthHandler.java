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

package org.wso2.carbon.identity.inbound.auth.oauth2new.handler.client;

import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2.ClientType;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;

/*
 * To authenticate OAuth2 clients
 */
public abstract class ClientAuthHandler extends AbstractIdentityMessageHandler {

    /**
     * Tells if the client is confidential or public.
     *
     * @return Returns the client type - confidential or public.
     */
    public abstract ClientType clientType(OAuth2MessageContext messageContext);

    /**
     * Authenticates the OAuth 2.0 client
     *
     * @param messageContext The runtime message context
     * @return Client ID if authentication was successful, {@code null} otherwise
     * @throws OAuth2Exception Error when authenticating the client
     */
    public abstract String authenticate(OAuth2MessageContext messageContext) throws OAuth2Exception;

}
