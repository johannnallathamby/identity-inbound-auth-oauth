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

package org.wso2.carbon.identity.inbound.auth.oidc.cache;

import org.wso2.carbon.identity.application.common.cache.CacheKey;

public abstract class OIDCCacheKey extends CacheKey {

    private static final long serialVersionUID = 6589756391127446125L;

    private String tokenId;
    private String tokenValue;

    public OIDCCacheKey(String tokenId, String tokenValue) {
        this.tokenId = tokenId;
        this.tokenValue = tokenValue;
    }

    public String getTokenId() {
        return tokenId;
    }

    public String getTokenValue() {
        return tokenValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OIDCCacheKey)) {
            return false;
        }

        OIDCCacheKey that = (OIDCCacheKey) o;

        if (!tokenId.equals(that.tokenId)) {
            return false;
        }
        return tokenValue.equals(that.tokenValue);

    }

    @Override
    public int hashCode() {
        int result = tokenId.hashCode();
        result = 31 * result + tokenValue.hashCode();
        return result;
    }
}
