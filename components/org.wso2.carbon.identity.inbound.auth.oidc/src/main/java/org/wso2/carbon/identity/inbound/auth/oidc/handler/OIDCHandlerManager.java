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

package org.wso2.carbon.identity.inbound.auth.oidc.handler;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.wso2.carbon.identity.core.handler.MessageHandlerComparator;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oidc.exception.OIDCRuntimeException;
import org.wso2.carbon.identity.inbound.auth.oidc.internal.OIDCDataHolder;

import java.util.Collections;
import java.util.List;

public class OIDCHandlerManager {

    private static volatile OIDCHandlerManager instance = new OIDCHandlerManager();

    private OIDCHandlerManager() {

    }

    public static OIDCHandlerManager getInstance() {
        return instance;
    }

    public IDTokenClaimsSet buildIDToken(OAuth2MessageContext messageContext) {

        List<IDTokenHandler> handlers = OIDCDataHolder.getInstance().getIDTokenHandlers();
        Collections.sort(handlers, new MessageHandlerComparator(messageContext));
        for(IDTokenHandler handler:handlers){
            if(handler.isEnabled(messageContext) && handler.canHandle(messageContext)){
                return handler.buildIDToken(messageContext);
            }
        }
        throw OIDCRuntimeException.error("Cannot find IDTokenHandler to handle this request");
    }
}
