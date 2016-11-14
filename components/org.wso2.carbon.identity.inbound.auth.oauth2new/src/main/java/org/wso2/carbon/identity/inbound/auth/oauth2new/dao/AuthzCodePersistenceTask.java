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
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;

import java.util.concurrent.BlockingDeque;

public class AuthzCodePersistenceTask implements Runnable {

    private static Log log = LogFactory.getLog(AuthzCodePersistenceTask.class);

    private BlockingDeque<AuthzCodeJob> authzCodeJobQueue;
    private OAuth2DAO persistentDAO;

    public AuthzCodePersistenceTask(BlockingDeque<AuthzCodeJob> authzCodeJobQueue, OAuth2DAO persistentDAO) {
        this.authzCodeJobQueue = authzCodeJobQueue;
        this.persistentDAO = persistentDAO;
    }

    @Override
    public void run() {

        if(log.isDebugEnabled()) {
            log.debug("AuthzCodePersistenceTask is started");
        }

        while (true) {
            try {
                AuthzCodeJob authzCodeJob = authzCodeJobQueue.take();
                if (authzCodeJob != null) {
                    if (authzCodeJob.action == AuthzCodeJob.AuthzCodeJobAction.UPDATE) {
                        persistentDAO.updateAuthzCodeState(authzCodeJob.authorizationCode, authzCodeJob.authzCodeState,
                                                           authzCodeJob.messageContext);
                    } else if (authzCodeJob.action == AuthzCodeJob.AuthzCodeJobAction.STORE) {
                        persistentDAO.storeAuthzCode(authzCodeJob.authzCode, authzCodeJob.messageContext);
                    }
                }
            } catch (InterruptedException | OAuth2RuntimeException e) {
                log.error("Error occurred while running task for task for AuthzCodeJob", e);
            }

        }
    }

    static class AuthzCodeJob {

        private enum AuthzCodeJobAction {
            STORE, UPDATE;
        }

        private AuthzCodeJobAction action;
        private AuthzCode authzCode;
        private String authorizationCode;
        private String authzCodeState;
        OAuth2MessageContext messageContext;

        AuthzCodeJob(AuthzCode authzCode) {
            this.authzCode = authzCode;
            this.action = AuthzCodeJobAction.STORE;
        }

        AuthzCodeJob(String authorizationCode, String authzCodeState) {
            this.authorizationCode = authorizationCode;
            this.authzCodeState = authzCodeState;
            this.action = AuthzCodeJobAction.UPDATE;
        }
    }

}
