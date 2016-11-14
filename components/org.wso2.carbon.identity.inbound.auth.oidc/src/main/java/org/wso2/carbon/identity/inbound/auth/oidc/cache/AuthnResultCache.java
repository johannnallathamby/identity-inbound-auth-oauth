/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
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
public class AuthnResultCache extends BaseCache<AuthnResultCacheKey, AuthnResultCacheEntry> {

    private static final Log log = LogFactory.getLog(AuthnResultCache.class);

    private static final String USER_ATTRIBUTE_CACHE = "UserAttributeCache";
    private static volatile AuthnResultCache instance;

    private AuthnResultCache() {
        super(USER_ATTRIBUTE_CACHE);
    }

    public static AuthnResultCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (AuthnResultCache.class) {
                if (instance == null) {
                    instance = new AuthnResultCache();
                }
            }
        }
        return instance;
    }

    public AuthnResultCacheEntry getValueFromCache(AuthnResultCacheKey key) {

        AuthnResultCacheEntry entry = super.getValueFromCache(key);
        if (entry == null) {
            entry = getFromSessionStore(key.getTokenId());
        }
        return entry;
    }

    public void addToCache(AuthnResultCacheKey key, AuthnResultCacheEntry entry) {

        storeToSessionStore(key.getTokenId(), entry);
        super.addToCache(key, entry);
    }

    public void clearCacheEntry(AuthnResultCacheKey key) {
        super.clearCacheEntry(key);
        clearFromSessionStore(key.getTokenId());
    }

    private AuthnResultCacheEntry getFromSessionStore(String id) {
        return (AuthnResultCacheEntry) SessionDataStore.getInstance().getSessionData(id, USER_ATTRIBUTE_CACHE);
    }

    private void storeToSessionStore(String id, AuthnResultCacheEntry entry) {
        SessionDataStore.getInstance().storeSessionData(id, USER_ATTRIBUTE_CACHE, entry);
    }

    private void clearFromSessionStore(String id) {
        SessionDataStore.getInstance().clearSessionData(id, USER_ATTRIBUTE_CACHE);
    }
}
