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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;

import java.io.Serializable;
import java.util.Map;

/*
 * Message context that holds information about the request to an endpoint
 */
public class OAuth2MessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {

    private static final long serialVersionUID = -3793959181562481432L;

    protected OAuth2App application;

    public OAuth2MessageContext(OAuth2IdentityRequest request, Map<T1,T2> parameters) {
        super(request, parameters);
    }

    /**
     * Uncomment after adding default constructor to framework and updating framework dependency version
     *
     * This constructor is deprecated because any processor using {@link OAuth2MessageContext} must create a
     * {@link OAuth2IdentityRequest} object.
     */
//    @Deprecated
//    public OAuth2MessageContext() {
//
//    }

    public void setApplication(OAuth2App application) {
        this.application = application;
    }

    @Override
    public OAuth2IdentityRequest getRequest(){
        return (OAuth2IdentityRequest)request;
    }

    public OAuth2App getApplication() {
        return application;
    }
}
