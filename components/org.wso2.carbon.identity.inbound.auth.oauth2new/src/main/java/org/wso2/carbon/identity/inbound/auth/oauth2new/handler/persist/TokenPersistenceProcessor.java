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

package org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist;

import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;

/**
 * To process OAuth2 tokens just before storing them in the database.
 * E.g. to encrypt tokens before storing them in the database.
 */
public abstract class TokenPersistenceProcessor extends AbstractIdentityMessageHandler {

    // TODO: move this implementation to framework, remove it from here and update framework dependency version
    public String getName() {
        return this.getClass().getSimpleName();
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return true;
    }

    public abstract String getProcessedClientId(String clientId);

    public abstract String getPreprocessedClientId(String processedClientId);

    public abstract String getProcessedClientSecret(String clientSecret);

    public abstract String getPreprocessedClientSecret(String processedClientSecret);

    public abstract String getProcessedAuthzCode(String authzCode);

    public abstract String getPreprocessedAuthzCode(String processedAuthzCode);

    public abstract String getProcessedAccessToken(String accessToken);

    public abstract String getPreprocessedAccessToken(String processedAccessToken);

    public abstract String getProcessedRefreshToken(String refreshToken);

    public abstract String getPreprocessedRefreshToken(String processedRefreshToken);

}
