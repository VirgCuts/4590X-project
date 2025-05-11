package com.carter.awsvalidator;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public class IAMRoleScanner {
    private final IamClient iam;
    private final ObjectMapper mapper;

    public IAMRoleScanner() {
        this.iam = IamClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
        this.mapper = new ObjectMapper();
    }

    public void scanRoles() {
        System.out.println("🔍 Scanning IAM Roles for overly permissive policies...");

        ListRolesResponse response = iam.listRoles();
        for (Role role : response.roles()) {
            System.out.println("\n🧑‍💼 Role: " + role.roleName());

            checkInlinePolicies(role.roleName());
            checkAttachedPolicies(role.roleName());
        }
    }

    private void checkInlinePolicies(String roleName) {
        ListRolePoliciesResponse inlineList = iam.listRolePolicies(ListRolePoliciesRequest.builder().roleName(roleName).build());

        for (String policyName : inlineList.policyNames()) {
            GetRolePolicyResponse policy = iam.getRolePolicy(GetRolePolicyRequest.builder()
                    .roleName(roleName)
                    .policyName(policyName)
                    .build());

            System.out.println("📄 Inline Policy: " + policyName);
            analyzePolicy(policy.policyDocument());
        }
    }

    private void checkAttachedPolicies(String roleName) {
        ListAttachedRolePoliciesResponse attached = iam.listAttachedRolePolicies(ListAttachedRolePoliciesRequest.builder()
                .roleName(roleName)
                .build());

        for (AttachedPolicy attachedPolicy : attached.attachedPolicies()) {
            GetPolicyResponse getPolicy = iam.getPolicy(GetPolicyRequest.builder()
                    .policyArn(attachedPolicy.policyArn())
                    .build());

            GetPolicyVersionResponse policyVersion = iam.getPolicyVersion(GetPolicyVersionRequest.builder()
                    .policyArn(attachedPolicy.policyArn())
                    .versionId(getPolicy.policy().defaultVersionId())
                    .build());

            System.out.println("📎 Attached Policy: " + attachedPolicy.policyName());
            analyzePolicy(policyVersion.policyVersion().document());
        }
    }

    private void analyzePolicy(String encodedPolicy) {
        try {
            // Decode the URL-encoded policy if needed
            String decoded = java.net.URLDecoder.decode(encodedPolicy, java.nio.charset.StandardCharsets.UTF_8);
            JsonNode root = mapper.readTree(decoded);
            JsonNode statements = root.get("Statement");

            if (statements.isArray()) {
                for (JsonNode stmt : statements) {
                    analyzeStatement(stmt);
                }
            } else {
                analyzeStatement(statements); // single statement
            }
        } catch (Exception e) {
            System.err.println("⚠️  Failed to parse policy document: " + e.getMessage());
        }
    }

    private void analyzeStatement(JsonNode stmt) {
        JsonNode effect = stmt.get("Effect");
        JsonNode action = stmt.get("Action");
        JsonNode resource = stmt.get("Resource");

        if (effect == null || !effect.asText().equalsIgnoreCase("Allow")) return;

        boolean actionIsWildcard = action != null && (action.toString().contains("*") || action.asText().equals("*"));
        boolean resourceIsWildcard = resource != null && (resource.toString().contains("*") || resource.asText().equals("*"));

        if (actionIsWildcard && resourceIsWildcard) {
            System.out.println("❌ CRITICAL: Wildcard action and resource (full admin access!)");
        } else if (actionIsWildcard) {
            System.out.println("⚠️  WARNING: Wildcard action found: " + action);
        } else if (resourceIsWildcard) {
            System.out.println("⚠️  WARNING: Wildcard resource access: " + resource);
        }

        if (action.toString().contains("iam:PassRole")) {
            System.out.println("⚠️  WARNING: Contains iam:PassRole, check for privilege escalation risks.");
        }

        if (action.toString().contains("sts:AssumeRole")) {
            System.out.println("⚠️  WARNING: Allows sts:AssumeRole, verify trust relationships.");
        }
    }

    public void close() {
        iam.close();
    }
}
