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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Stores authenticated user attributes and OpenID Connect specific attributes during OIDC Authorization request
 * processing. Those values are later required to serve OIDC Token request and build IDToken.
 */
public class OIDCCache extends BaseCache<OIDCCacheKey, OIDCCacheEntry> {

    private static final Log log = LogFactory.getLog(OIDCCache.class);

    private static final String OIDC_CACHE = "OIDCCache";
    private static volatile OIDCCache instance;

    private OIDCCache() {
        super(OIDC_CACHE);
    }

    public static OIDCCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (OIDCCache.class) {
                if (instance == null) {
                    instance = new OIDCCache();
                }
            }
        }
        return instance;
    }

    public OIDCCacheEntry getValueFromCache(OIDCCacheKey key) {

        OIDCCacheEntry entry = super.getValueFromCache(key);
        if (entry == null) {
            entry = getFromSessionStore(key.getTokenId());
        }
        return entry;
    }

    public void addToCache(OIDCCacheKey key, OIDCCacheEntry entry) {

        storeToSessionStore(key.getTokenId(), entry);
        super.addToCache(key, entry);
    }

    public void clearCacheEntry(OIDCCacheKey key) {
        super.clearCacheEntry(key);
        clearFromSessionStore(key.getTokenId());
    }

    private OIDCCacheEntry getFromSessionStore(String id) {
        return (OIDCCacheEntry) SessionDataStore.getInstance().getSessionData(id, OIDC_CACHE);
    }

    private void storeToSessionStore(String id, OIDCCacheEntry entry) {
        SessionDataStore.getInstance().storeSessionData(id, OIDC_CACHE, entry);
    }

    private void clearFromSessionStore(String id) {
        SessionDataStore.getInstance().clearSessionData(id, OIDC_CACHE);
    }
}
