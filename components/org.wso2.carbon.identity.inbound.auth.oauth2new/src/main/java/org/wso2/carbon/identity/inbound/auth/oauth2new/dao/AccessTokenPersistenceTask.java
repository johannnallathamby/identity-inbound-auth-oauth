/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.inbound.auth.oauth2new.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;

import java.util.concurrent.BlockingDeque;

public class AccessTokenPersistenceTask implements Runnable {

    private static Log log = LogFactory.getLog(AccessTokenPersistenceTask.class);

    private BlockingDeque<AccessTokenJob> accessTokenJobQueue;
    private OAuth2DAO persistentDAO;

    public AccessTokenPersistenceTask(BlockingDeque<AccessTokenJob> accessTokenJobQueue, OAuth2DAO persistentDAO) {
        this.accessTokenJobQueue = accessTokenJobQueue;
        this.persistentDAO = persistentDAO;
    }

    @Override
    public void run() {

        if(log.isDebugEnabled()) {
            log.debug("AccessTokenPersistenceTask is started");
        }

        while (true) {
            AccessTokenJob job = null;
            try {
                job = accessTokenJobQueue.take();
                if (job != null) {
                    persistentDAO.storeAccessToken(job.newAccessToken, job.oldAccessToken, job.authzCode, job.messageContext);
                }
            } catch (InterruptedException | OAuth2RuntimeException e) {
                log.error("Error occurred while running task for AccessTokenJob", e);
            }
        }
    }

    static class AccessTokenJob {

        AccessToken newAccessToken;
        String oldAccessToken;
        String authzCode;
        OAuth2MessageContext messageContext;

        AccessTokenJob(AccessToken newAccessToken) {
            this.newAccessToken = newAccessToken;
        }

        void setOldAccessToken(String oldAccessToken) {
            this.oldAccessToken = oldAccessToken;
        }

        void setAuthzCode(String authzCode) {
            this.authzCode = authzCode;
        }

        void setMessageContext(OAuth2MessageContext messageContext) {
            this.messageContext = messageContext;
        }
    }
}
