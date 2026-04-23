package org.wso2.carbon.identity.device.policy.management.internal.rule;

import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationResult;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class DevicePolicyEvaluator {

    private static final String HEADER_PREFIX = "X-Device-";

    private static final String[] DEVICE_FIELDS = {
            "platform",
            "osVersion",
            "isRooted",
            "usbDebugging",
            "lockScreen",
            "biometric",
            "screenLockComplexity",
            "hardwareKeystore",
            "diskEncryption",
            "networkProxies",
            "wifiNetworkSecurity",
            "passcode",
            "touchIdOrFaceId",
            "jailbreak",
            "secureEnclave",
            "windowsHello",
            "trustedPlatformModule"
    };

    private static final Map<String, String> FIELD_TO_HEADER = new HashMap<>();

    static {
        FIELD_TO_HEADER.put("platform",             "X-Device-Platform");
        FIELD_TO_HEADER.put("osVersion",            "X-Device-OS-Version");
        FIELD_TO_HEADER.put("isRooted",             "X-Device-Is-Rooted");
        FIELD_TO_HEADER.put("usbDebugging",         "X-Device-USB-Debugging");
        FIELD_TO_HEADER.put("lockScreen",           "X-Device-Lock-Screen");
        FIELD_TO_HEADER.put("biometric",            "X-Device-Biometric");
        FIELD_TO_HEADER.put("screenLockComplexity", "X-Device-Screen-Lock-Complexity");
        FIELD_TO_HEADER.put("hardwareKeystore",     "X-Device-Hardware-Keystore");
        FIELD_TO_HEADER.put("diskEncryption",       "X-Device-Disk-Encryption");
        FIELD_TO_HEADER.put("networkProxies",       "X-Device-Network-Proxies");
        FIELD_TO_HEADER.put("wifiNetworkSecurity",  "X-Device-Wifi-Network-Security");
        FIELD_TO_HEADER.put("passcode",             "X-Device-Passcode");
        FIELD_TO_HEADER.put("touchIdOrFaceId",      "X-Device-Touch-Id-Or-Face-Id");
        FIELD_TO_HEADER.put("jailbreak",            "X-Device-Jailbreak");
        FIELD_TO_HEADER.put("secureEnclave",        "X-Device-Secure-Enclave");
        FIELD_TO_HEADER.put("windowsHello",         "X-Device-Windows-Hello");
        FIELD_TO_HEADER.put("trustedPlatformModule","X-Device-Trusted-Platform-Module");
    }

    /**
     * Evaluates device policy compliance.
     *
     * @return null if compliant, or a comma-separated string of failed field names if not compliant.
     */
    public String evaluate(String policyName, HttpServletRequest request, String tenantDomain)
            throws PolicyManagementException, RuleEvaluationException {

        // Step 1 - get the policy to find ruleId
        Policy policy = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getPolicyManagementService()
                .getPolicyByName(policyName, tenantDomain);

        // Step 2 - build device data map from request headers
        Map<String, Object> deviceData = new HashMap<>();
        for (String field : DEVICE_FIELDS) {
            String headerName = FIELD_TO_HEADER.get(field);
            String value = request.getHeader(headerName);
            if (value != null) {
                deviceData.put(field, value);
            }
        }

        // Step 3 - build FlowContext
        FlowContext flowContext = new FlowContext(FlowType.DEVICE_POLICY, deviceData);

        // Step 4 - evaluate
        RuleEvaluationResult result = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getRuleEvaluationService()
                .evaluate(policy.getRuleId(), flowContext, tenantDomain);

        // Step 5 - return null if satisfied, or the failed field names joined
        if (result.isRuleSatisfied()) {
            return null;
        }
        return String.join(", ", result.getFailedFields());
    }
}