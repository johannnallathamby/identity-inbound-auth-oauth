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

package org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.assertion.saml2;

import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;

public class SAML2BearerGrantException extends OAuth2ClientException {

    protected SAML2BearerGrantException(String errorDescription) {
        super(errorDescription);
    }

    protected SAML2BearerGrantException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }

    public static SAML2BearerGrantException error(String errorDescription){
        return new SAML2BearerGrantException(errorDescription);
    }

    public static SAML2BearerGrantException error(String errorDescription, Throwable cause){
        return new SAML2BearerGrantException(errorDescription, cause);
    }
}
