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

package org.wso2.carbon.identity.inbound.auth.oauth2new.introspect;

import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;

import java.io.Serializable;
import java.util.Map;

/*
 * Message context that holds information about the token introspection request to the token introspection endpoint
 */
public class IntrospectionMessageContext<T1 extends Serializable, T2 extends Serializable> extends
        OAuth2MessageContext {

    private static final long serialVersionUID = 8957814451266828857L;

    private String clientId;

    public IntrospectionMessageContext(IntrospectionRequest request, Map<T1, T2> parameters) {
        super(request, parameters);
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

}
