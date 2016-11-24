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

package org.wso2.carbon.identity.inbound.auth.oauth2new.revoke;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class RevocationResponse extends IdentityResponse {

    private String callback;

    protected RevocationResponse(RevocationResponseBuilder builder) {
        super(builder);
        this.callback = builder.callback;
    }

    public String getCallback() {
        return this.callback;
    }

    public static class RevocationResponseBuilder extends IdentityResponseBuilder {

        private String callback;

        public RevocationResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public RevocationResponseBuilder setCallback(String callback) {
            this.callback = callback;
            return this;
        }

        public RevocationResponse build() {
            return new RevocationResponse(this);
        }
    }
}
