/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.device.registration.executor;

/**
 * Constants shared between {@link DeviceRegistrationExecutor} and
 * {@link RegistrationFlowCompletionListener}.
 */
public class DeviceRegistrationExecutorConstants {

    /**
     * Unique executor name used by the flow execution engine registry.
     */
    public static final String EXECUTOR_NAME = "DeviceRegistrationExecutor";

    /**
     * Flow context key holding the verified-but-not-yet-persisted Device in
     * REGISTRATION flows. Written by DeviceRegistrationExecutor in Phase 2 and read by
     * RegistrationFlowCompletionListener after UserProvisioningExecutor assigns the real userId.
     */
    public static final String CTX_DEVICE_REGISTRATION = "device.registration.data";

    private DeviceRegistrationExecutorConstants() {

    }
}
