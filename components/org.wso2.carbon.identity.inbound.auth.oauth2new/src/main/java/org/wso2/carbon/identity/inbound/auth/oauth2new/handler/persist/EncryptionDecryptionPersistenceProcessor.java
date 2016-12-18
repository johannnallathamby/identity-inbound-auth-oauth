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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;

/**
 * Stores encrypted tokens in the database.
 * TODO: Not working. Need to test.
 */
public class EncryptionDecryptionPersistenceProcessor extends TokenPersistenceProcessor {

    protected Log log = LogFactory.getLog(EncryptionDecryptionPersistenceProcessor.class);

    @Override
    public String getProcessedClientId(String clientId) {
        try {
            return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(clientId.getBytes());
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getPreprocessedClientId(String processedClientId) {
        try {
            return new String(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(processedClientId));
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getProcessedClientSecret(String clientSecret) {
        try {
            return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(clientSecret.getBytes());
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getPreprocessedClientSecret(String processedClientSecret) {
        try {
            return new String(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(processedClientSecret));
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getProcessedAuthzCode(String authzCode) {
        try {
            return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(authzCode.getBytes());
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getPreprocessedAuthzCode(String processedAuthzCode) {
        try {
            return new String(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(processedAuthzCode));
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getProcessedAccessToken(String accessToken) {
        try {
            return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(accessToken.getBytes());
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getPreprocessedAccessToken(String processedAccessToken) {
        try {
            return new String(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(processedAccessToken));
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getProcessedRefreshToken(String refreshToken) {
        try {
            return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(refreshToken.getBytes());
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }

    @Override
    public String getPreprocessedRefreshToken(String processedRefreshToken) {
        try {
            return new String(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(processedRefreshToken));
        } catch (CryptoException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
    }
}
