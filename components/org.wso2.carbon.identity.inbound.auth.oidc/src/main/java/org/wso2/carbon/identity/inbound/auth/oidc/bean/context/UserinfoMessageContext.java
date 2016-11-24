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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.context;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionResponse;

import java.io.Serializable;
import java.util.Map;

public class UserinfoMessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {

    protected IntrospectionRequest introspectionRequest;
    protected IntrospectionResponse introspectionResponse;

    public UserinfoMessageContext(IdentityRequest userinfoRequest, Map<T1, T2> parameters) {
        super(userinfoRequest, parameters);
    }

    public IdentityRequest getRequest(){
        return  request;
    }

    public IntrospectionRequest getIntrospectionRequest(){
        return introspectionRequest;
    }

    public IntrospectionResponse getIntrospectionResponse(){
        return introspectionResponse;
    }

    public void setIntrospectionRequest(IntrospectionRequest introspectionRequest){
        this.introspectionRequest = introspectionRequest;
    }

    public void setIntrospectionResponse(IntrospectionResponse introspectionResponse){
        this.introspectionResponse = introspectionResponse;
    }
}
