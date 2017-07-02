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

package org.wso2.carbon.identity.inbound.auth.oidc.exception;

import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;

public class OIDCClientException extends OAuth2ClientException {

    public OIDCClientException(String message) {
        super(message);
    }

    public OIDCClientException(String message, Throwable cause) {
        super(message, cause);
    }

    public static OIDCClientException error(String message) {
        return new OIDCClientException(message);
    }

    public static OIDCClientException error(String message, Throwable cause) {
        return new OIDCClientException(message, cause);
    }
}
