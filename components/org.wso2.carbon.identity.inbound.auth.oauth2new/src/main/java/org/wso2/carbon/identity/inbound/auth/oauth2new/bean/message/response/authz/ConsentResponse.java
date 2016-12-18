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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;

import java.util.HashMap;
import java.util.Map;

public class ConsentResponse extends ROApprovalResponse {

    private static final long serialVersionUID = 2175011133147174197L;

    private String sessionDataKeyConsent;

    private String applicationName;

    private String authenticatedSubjectId;

    private Map<String,String[]> parameterMap = new HashMap();

    public String getSessionDataKeyConsent() {
        return sessionDataKeyConsent;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public String getAuthenticatedSubjectId() {
        return authenticatedSubjectId;
    }

    public Map<String, String[]> getParameterMap() {
        return parameterMap;
    }

    protected ConsentResponse(ConsentResponseBuilder builder) {
        super(builder);
        this.sessionDataKeyConsent = builder.sessionDataKeyConsent;
        this.applicationName = builder.applicationName;
        this.authenticatedSubjectId = builder.authenticatedSubjectId;
        this.parameterMap = builder.parameterMap;
    }

    public static class ConsentResponseBuilder extends ROApprovalResponseBuilder {

        private String sessionDataKeyConsent;

        private String applicationName;

        private String authenticatedSubjectId;


        private Map<String,String[]> parameterMap = new HashMap();

        public ConsentResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public ConsentResponseBuilder setSessionDataKeyConsent(String sessionDataKeyConsent) {
            this.sessionDataKeyConsent = sessionDataKeyConsent;
            return this;
        }

        public ConsentResponseBuilder setApplicationName(String applicationName) {
            this.applicationName = applicationName;
            return this;
        }

        public ConsentResponseBuilder setAuthenticatedSubjectId(String authenticatedSubjectId) {
            this.authenticatedSubjectId = authenticatedSubjectId;
            return this;
        }

        public ConsentResponseBuilder setParameterMap(Map<String, String[]> parameterMap) {
            if(parameterMap != null) {
                this.parameterMap = parameterMap;
            }
            return this;
        }

        public ConsentResponse build() {
            return new ConsentResponse(this);
        }
    }
}
