package com.carter.awsvalidator;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.AttachedPolicy;
import software.amazon.awssdk.services.iam.model.GenerateServiceLastAccessedDetailsRequest;
import software.amazon.awssdk.services.iam.model.GenerateServiceLastAccessedDetailsResponse;
import software.amazon.awssdk.services.iam.model.GetAccountPasswordPolicyResponse;
import software.amazon.awssdk.services.iam.model.GetPolicyRequest;
import software.amazon.awssdk.services.iam.model.GetPolicyResponse;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionRequest;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionResponse;
import software.amazon.awssdk.services.iam.model.GetRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.GetRolePolicyResponse;
import software.amazon.awssdk.services.iam.model.GetServiceLastAccessedDetailsRequest;
import software.amazon.awssdk.services.iam.model.GetServiceLastAccessedDetailsResponse;
import software.amazon.awssdk.services.iam.model.GetUserResponse;
import software.amazon.awssdk.services.iam.model.IamException;
import software.amazon.awssdk.services.iam.model.JobStatusType;
import software.amazon.awssdk.services.iam.model.ListAccessKeysRequest;
import software.amazon.awssdk.services.iam.model.ListAccessKeysResponse;
import software.amazon.awssdk.services.iam.model.ListAttachedRolePoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListAttachedRolePoliciesResponse;
import software.amazon.awssdk.services.iam.model.ListRolePoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListRolePoliciesResponse;
import software.amazon.awssdk.services.iam.model.ListRolesResponse;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.iam.model.PasswordPolicy;
import software.amazon.awssdk.services.iam.model.Role;
import software.amazon.awssdk.services.iam.model.ServiceLastAccessed;

public class IAMRoleScanner {
    private final IamClient iamClient;
    private final List<SecurityIssue> issues = new ArrayList<>();

    private static final String RESET = "\u001B[0m";
    private static final String CYAN = "\u001B[36m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String ORANGE = "\u001B[38;5;208m";

    // Constants for security checks
    private static final int MAX_INACTIVE_DAYS = 90;
    private static final int MAX_CREDENTIALS_AGE_DAYS = 90;
    private static final int PASSWORD_POLICY_MIN_LENGTH = 14;
    private static final Set<String> RISKY_PERMISSIONS = new HashSet<String>() {{
        add("*:*");
        add("iam:*");
        add("sts:AssumeRole");
        add("s3:*");
        add("ec2:*");
        add("lambda:*");
        add("dynamodb:*");
        add("cloudformation:*");
    }};

    public IAMRoleScanner() {
        this.iamClient = IamClient.builder()
                .region(Region.AWS_GLOBAL)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    public List<SecurityIssue> scanRoles() {
        System.out.println(CYAN+ "Scanning IAM Roles for security issues..." + RESET);
        issues.clear();

        try {
            // List all roles in the account
            ListRolesResponse rolesResponse = iamClient.listRoles();
            for (Role role : rolesResponse.roles()) {
                String roleName = role.roleName();
                System.out.println("\nRole: " + roleName);
                
                // Run all security checks for this role
                checkAdminAccess(role);
                checkAssumeRolePolicy(role);
                checkInlinePolicies(roleName);
                checkAttachedPolicies(roleName);
                checkServiceAccess(role);
                checkLastActivity(roleName);
                checkMFA(role);
                checkPermissionBoundaries(role);
            }
            
            // Account-level checks
            checkRootUserAccessKeys();
            checkPasswordPolicy();
            
        } catch (IamException e) {
            System.out.println("Error scanning IAM roles: " + e.getMessage());
        }

        return issues;
    }
    public void printAllIssuesBySeverity() {
    if (issues.isEmpty()) {
        System.out.println(GREEN + "No security issues found." + RESET);
        return;
    }

    System.out.println("\n### SECURITY ISSUES BY SEVERITY ###");

    SecuritySeverity[] severityOrder = {
        SecuritySeverity.CRITICAL,
        SecuritySeverity.HIGH,
        SecuritySeverity.MEDIUM,
        SecuritySeverity.LOW
    };

    for (SecuritySeverity severity : severityOrder) {
        List<SecurityIssue> filtered = getIssuesBySeverity(severity);
        if (filtered.isEmpty()) continue;

        String color;
        switch (severity) {
            case CRITICAL: color = RED; break;
            case HIGH:     color = ORANGE; break;
            case MEDIUM:   color = YELLOW; break;
            case LOW:      color = GREEN; break;
            default:       color = RESET;
        }

        System.out.println(color + "\n[" + severity + "] Issues:" + RESET);
        for (SecurityIssue issue : filtered) {
            System.out.println(" - " + issue.getTitle());
            System.out.println("   Description: " + issue.getDescription());
            System.out.println("   Recommendation: " + issue.getRecommendation());
            System.out.println();
            }
        }
    }
    //made public so they can be called in main
    public void printSummary() {
        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        
        for (SecurityIssue issue : issues) {
            switch (issue.getSeverity()) {
                case CRITICAL:
                    criticalCount++;
                    break;
                case HIGH:
                    highCount++;
                    break;
                case MEDIUM:
                    mediumCount++;
                    break;
                case LOW:
                    lowCount++;
                    break;
            }
        }

        System.out.println("\n### IAMROLE SCAN SUMMARY ###");
        System.out.println("---------------------------");
        System.out.println(RED + " CRITICAL: " + criticalCount + RESET);
        System.out.println(ORANGE + " HIGH:     " + highCount+ RESET);
        System.out.println(YELLOW +" MEDIUM:   " + mediumCount+ RESET);
        System.out.println(GREEN + " LOW:      " + lowCount+ RESET);
        System.out.println("---------------------------");
        System.out.println("TOTAL:     " + issues.size());
    }

    private void checkAdminAccess(Role role) {
        try {
            String policyDocument = role.assumeRolePolicyDocument();
            if (policyDocument != null && 
                (policyDocument.contains("\"Action\": \"*\"") || 
                 policyDocument.contains("\"Effect\": \"Allow\"") && 
                 policyDocument.contains("\"Resource\": \"*\""))) {
                
                System.out.println("Role has admin-like permissions!");
                issues.add(new SecurityIssue(
                    SecuritySeverity.CRITICAL,
                    "Role With Admin Access",
                    "Role " + role.roleName() + " has admin-like permissions with wildcard (*) resources",
                    "Limit the role permissions to only what is necessary for its function",
                    "Review and restrict permissions using the IAM console or AWS CLI"
                ));
            }
        } catch (Exception e) {
            System.out.println("Could not check admin access: " + e.getMessage());
        }
    }

    private void checkAssumeRolePolicy(Role role) {
        try {
            String policyDocument = role.assumeRolePolicyDocument();
            
            // Check for overly permissive trust relationships
            if (policyDocument != null) {
                if (policyDocument.contains("\"Principal\": \"*\"") || 
                    policyDocument.contains("\"Principal\": {\"AWS\": \"*\"}")) {
                    System.out.println("Role can be assumed by any AWS account!");
                    issues.add(new SecurityIssue(
                        SecuritySeverity.CRITICAL,
                        "Overly Permissive Trust Relationship",
                        "Role " + role.roleName() + " can be assumed by any AWS account",
                        "Restrict the trust relationship to specific accounts or services",
                        "Update the trust policy with specific AWS account IDs or service principals"
                    ));
                }
                
                // Check for public facing services in trust relationships
                if (policyDocument.contains("\"Service\": \"lambda.amazonaws.com\"") || 
                    policyDocument.contains("\"Service\": \"apigateway.amazonaws.com\"")) {
                    System.out.println("Role is assumable by public-facing services.");
                    issues.add(new SecurityIssue(
                        SecuritySeverity.MEDIUM,
                        "Public Service Trust Relationship",
                        "Role " + role.roleName() + " can be assumed by public-facing services",
                        "Ensure proper authorization is in place for these services",
                        "Review the services that can assume this role and implement proper controls"
                    ));
                }
            }
        } catch (Exception e) {
            System.out.println("Could not check assume role policy: " + e.getMessage());
        }
    }

    private void checkInlinePolicies(String roleName) {
        try {
            ListRolePoliciesResponse policiesResp = iamClient.listRolePolicies(
                ListRolePoliciesRequest.builder().roleName(roleName).build());
            
            for (String policyName : policiesResp.policyNames()) {
                GetRolePolicyResponse policyResp = iamClient.getRolePolicy(
                    GetRolePolicyRequest.builder()
                        .roleName(roleName)
                        .policyName(policyName)
                        .build());
                
                String policyDocument = policyResp.policyDocument();
                
                // Check for wildcard permissions
                checkForWildcardPermissions(roleName, policyName, policyDocument, "inline");
            }
            
            if (policiesResp.policyNames().isEmpty()) {
                System.out.println("No inline policies found.");
            }
        } catch (Exception e) {
            System.out.println("Could not check inline policies: " + e.getMessage());
        }
    }

    private void checkAttachedPolicies(String roleName) {
        try {
            ListAttachedRolePoliciesResponse attachedPoliciesResp = iamClient.listAttachedRolePolicies(
                ListAttachedRolePoliciesRequest.builder().roleName(roleName).build());
            
            for (AttachedPolicy policy : attachedPoliciesResp.attachedPolicies()) {
                String policyArn = policy.policyArn();
                String policyName = policy.policyName();
                
                // Check if this is an AWS managed policy that grants admin access
                if (policyArn.contains("AdministratorAccess") || 
                    policyArn.contains("PowerUserAccess") || 
                    policyArn.contains("FullAccess")) {
                    System.out.println("Role has " + policyName + " policy attached!");
                    issues.add(new SecurityIssue(
                        SecuritySeverity.HIGH,
                        "Overly Permissive Managed Policy",
                        "Role " + roleName + " has the " + policyName + " policy attached, which grants extensive permissions",
                        "Replace with more restrictive policies that follow least privilege principle",
                        "aws iam detach-role-policy --role-name " + roleName + " --policy-arn " + policyArn
                    ));
                }
                
                // For customer managed policies, get the policy version to check content
                if (!policyArn.contains("arn:aws:iam::aws:")) {
                    try {
                        GetPolicyResponse policyResp = iamClient.getPolicy(
                            GetPolicyRequest.builder().policyArn(policyArn).build());
                        
                        String defaultVersionId = policyResp.policy().defaultVersionId();
                        
                        GetPolicyVersionResponse versionResp = iamClient.getPolicyVersion(
                            GetPolicyVersionRequest.builder()
                                .policyArn(policyArn)
                                .versionId(defaultVersionId)
                                .build());
                        
                        String policyDocument = versionResp.policyVersion().document();
                        
                        // Check for wildcard permissions
                        checkForWildcardPermissions(roleName, policyName, policyDocument, "managed");
                    } catch (Exception e) {
                        System.out.println("Could not check policy " + policyName + ": " + e.getMessage());
                    }
                }
            }
            
            if (attachedPoliciesResp.attachedPolicies().isEmpty()) {
                System.out.println("No managed policies attached to role.");
                issues.add(new SecurityIssue(
                    SecuritySeverity.LOW,
                    "No Managed Policies",
                    "Role " + roleName + " has no managed policies attached",
                    "Consider using AWS managed policies for standard use cases",
                    "Attach appropriate managed policies using the IAM console or AWS CLI"
                ));
            }
        } catch (Exception e) {
            System.out.println("Could not check attached policies: " + e.getMessage());
        }
    }

    private void checkForWildcardPermissions(String roleName, String policyName, String policyDocument, String policyType) {
        // Look for wildcard permissions in actions and resources
        for (String riskyPermission : RISKY_PERMISSIONS) {
            String service = riskyPermission.split(":")[0];
            String action = riskyPermission.split(":")[1];
            
            // Check for various patterns of the risky permission
            Pattern pattern = Pattern.compile(
                "\"Action\"\\s*:\\s*\\[?\\s*\"" + service + ":" + (action.equals("*") ? ".*" : action) + "\"\\s*\\]?,?.*?" +
                "\"Resource\"\\s*:\\s*\\[?\\s*\"\\*\"");
            
            Matcher matcher = pattern.matcher(policyDocument);
            if (matcher.find()) {
                System.out.println("" + policyType + " policy " + policyName + " contains risky permission: " + riskyPermission);
                issues.add(new SecurityIssue(
                    SecuritySeverity.HIGH,
                    "Wildcard Permission in Policy",
                    "Role " + roleName + " has " + policyType + " policy '" + policyName + "' with risky permission: " + riskyPermission,
                    "Limit permissions to specific resources and actions",
                    policyType.equals("inline") ? 
                        "aws iam get-role-policy --role-name " + roleName + " --policy-name " + policyName :
                        "Review policy using IAM console and apply principle of least privilege"
                ));
            }
        }
    }

    private void checkServiceAccess(Role role) {
        // Extract services from the trust policy
        try {
            String policyDocument = role.assumeRolePolicyDocument();
            if (policyDocument != null) {
                Pattern servicePattern = Pattern.compile("\"Service\"\\s*:\\s*\\[?\\s*\"([\\w\\.\\-]+)\"");
                Matcher matcher = servicePattern.matcher(policyDocument);
                
                while (matcher.find()) {
                    String service = matcher.group(1);
                    System.out.println("ℹRole can be assumed by service: " + service);
                    
                    // Check for deprecated or legacy services
                    if (service.contains("elasticbeanstalk") || 
                        service.contains("opsworks") || 
                        service.contains("elasticmapreduce")) {
                        System.out.println("Role uses legacy or deprecated service: " + service);
                        issues.add(new SecurityIssue(
                            SecuritySeverity.LOW,
                            "Legacy Service Trust Relationship",
                            "Role " + role.roleName() + " can be assumed by legacy service: " + service,
                            "Consider migrating to newer AWS services when possible",
                            "Review the need for this service and update trust relationship as needed"
                        ));
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Could not check service access: " + e.getMessage());
        }
    }

    private void checkLastActivity(String roleName) {
        try {
            // Get service last accessed data for the role
            GenerateServiceLastAccessedDetailsResponse genResp = iamClient.generateServiceLastAccessedDetails(
                GenerateServiceLastAccessedDetailsRequest.builder()
                    .arn("arn:aws:iam::" + getAccountId() + ":role/" + roleName)
                    .build());
            
            String jobId = genResp.jobId();
            
            // Wait for job to complete
            GetServiceLastAccessedDetailsResponse accessResp = null;
            JobStatusType status;
            do {
                Thread.sleep(1000); // Wait 1 second between checks
                accessResp = iamClient.getServiceLastAccessedDetails(
                    GetServiceLastAccessedDetailsRequest.builder()
                        .jobId(jobId)
                        .build());
                status = accessResp.jobStatus();
            } while (status == JobStatusType.IN_PROGRESS);
            
            if (status == JobStatusType.COMPLETED) {
                // Check if role has been inactive
                boolean anyRecentActivity = false;
                Instant cutoffDate = Instant.now().minus(MAX_INACTIVE_DAYS, ChronoUnit.DAYS);
                
                for (ServiceLastAccessed service : accessResp.servicesLastAccessed()) {
                    if (service.lastAuthenticated() != null && 
                        service.lastAuthenticated().isAfter(cutoffDate)) {
                        anyRecentActivity = true;
                        break;
                    }
                }
                
                if (!anyRecentActivity) {
                    System.out.println("Role has not been used in the last " + MAX_INACTIVE_DAYS + " days");
                    issues.add(new SecurityIssue(
                        SecuritySeverity.MEDIUM,
                        "Inactive Role",
                        "Role " + roleName + " has not been used in the last " + MAX_INACTIVE_DAYS + " days",
                        "Inactive roles should be removed to reduce security risks",
                        "aws iam delete-role --role-name " + roleName + " # (after removing attached policies)"
                    ));
                } else {
                    System.out.println("Role has recent activity.");
                }
            }
        } catch (Exception e) {
            System.out.println("Could not check last activity: " + e.getMessage());
        }
    }

    private void checkMFA(Role role) {
        try {
            String policyDocument = role.assumeRolePolicyDocument();
            if (policyDocument != null) {
                // Check if the policy requires MFA for AssumeRole
                boolean requiresMfa = policyDocument.contains("\"Condition\"") && 
                                     policyDocument.contains("\"Bool\"") && 
                                     policyDocument.contains("\"aws:MultiFactorAuthPresent\"") && 
                                     policyDocument.contains("\"true\"");
                
                if (!requiresMfa && policyDocument.contains("\"AWS\"")) {
                    System.out.println("Role can be assumed without MFA.");
                    issues.add(new SecurityIssue(
                        SecuritySeverity.MEDIUM,
                        "MFA Not Required",
                        "Role " + role.roleName() + " can be assumed by users without MFA",
                        "Add condition to require MFA for role assumption",
                        "Add MFA condition to trust policy using IAM console or AWS CLI"
                    ));
                } else if (requiresMfa) {
                    System.out.println("Role requires MFA for assumption.");
                }
            }
        } catch (Exception e) {
            System.out.println("Could not check MFA requirements: " + e.getMessage());
        }
    }

    private void checkPermissionBoundaries(Role role) {
        // Check if permission boundary is applied
        if (role.permissionsBoundary() == null) {
            System.out.println("No permission boundary applied to the role.");
            issues.add(new SecurityIssue(
                SecuritySeverity.LOW,
                "No Permission Boundary",
                "Role " + role.roleName() + " does not have a permission boundary",
                "Consider applying a permission boundary for additional security",
                "aws iam put-role-permissions-boundary --role-name " + role.roleName() + 
                " --permissions-boundary YourPermissionBoundaryPolicyArn"
            ));
        } else {
            System.out.println("Role has a permission boundary.");
        }
    }

    private void checkRootUserAccessKeys() {
        try {
            ListAccessKeysResponse keysResp = iamClient.listAccessKeys(
                ListAccessKeysRequest.builder().userName("root").build());
            
            if (!keysResp.accessKeyMetadata().isEmpty()) {
                System.out.println("ROOT USER HAS ACCESS KEYS!");
                issues.add(new SecurityIssue(
                    SecuritySeverity.CRITICAL,
                    "Root User Access Keys",
                    "The AWS root user has active access keys, which is a security risk",
                    "Delete all access keys for the root user immediately",
                    "Log in as root user and delete all access keys from Security Credentials page"
                ));
            }
        } catch (NoSuchEntityException e) {
            // This is expected - "root" is not a regular IAM user
        } catch (Exception e) {
            System.out.println("Could not check root user access keys: " + e.getMessage());
        }
    }

    private void checkPasswordPolicy() {
    try {
        GetAccountPasswordPolicyResponse policyResp = iamClient.getAccountPasswordPolicy();
        PasswordPolicy policy = policyResp.passwordPolicy();
        
        // Check password policy strength
        if (policy.minimumPasswordLength() < PASSWORD_POLICY_MIN_LENGTH) {
            System.out.println("Weak password policy: minimum length is less than " + PASSWORD_POLICY_MIN_LENGTH);
            issues.add(new SecurityIssue(
                SecuritySeverity.MEDIUM,
                "Weak Password Policy",
                "Account password policy requires passwords of only " + policy.minimumPasswordLength() + " characters",
                "Increase minimum password length to at least " + PASSWORD_POLICY_MIN_LENGTH + " characters",
                "aws iam update-account-password-policy --minimum-password-length " + PASSWORD_POLICY_MIN_LENGTH
            ));
        }
        
        if (!policy.requireSymbols() || !policy.requireNumbers() || 
            !policy.requireUppercaseCharacters() || !policy.requireLowercaseCharacters()) {
            System.out.println("Weak password policy: missing character type requirements");
            issues.add(new SecurityIssue(
                SecuritySeverity.MEDIUM,
                "Weak Password Policy",
                "Account password policy does not require all character types (uppercase, lowercase, numbers, symbols)",
                "Update password policy to require all character types",
                "aws iam update-account-password-policy --require-symbols --require-numbers " +
                "--require-uppercase-characters --require-lowercase-characters"
            ));
        }
        
        // FIX: Check if passwordReusePrevention is null or less than 24
        // Instead of !policy.passwordReusePrevention()
        if (policy.passwordReusePrevention() == null || policy.passwordReusePrevention() < 24) {
            System.out.println("Weak password policy: insufficient password reuse prevention");
            issues.add(new SecurityIssue(
                SecuritySeverity.LOW,
                "Weak Password Reuse Prevention",
                "Account password policy does not prevent reuse of recent passwords",
                "Configure password policy to remember the last 24 passwords",
                "aws iam update-account-password-policy --password-reuse-prevention 24"
            ));
        }
        
        // FIX: Check if expirePasswords is false or maxPasswordAge is null or too large
        // Instead of !policy.expirePasswords() || policy.maxPasswordAge() > 90
        if (!policy.expirePasswords() || policy.maxPasswordAge() == null || policy.maxPasswordAge() > 90) {
            System.out.println("Weak password policy: passwords don't expire or expire too infrequently");
            issues.add(new SecurityIssue(
                SecuritySeverity.LOW,
                "Weak Password Expiration",
                "Account password policy does not require regular password changes",
                "Configure password policy to expire passwords after 90 days",
                "aws iam update-account-password-policy --max-password-age 90"
            ));
        }
    } catch (NoSuchEntityException e) {
        System.out.println("No account password policy found!");
        issues.add(new SecurityIssue(
            SecuritySeverity.HIGH,
            "No Password Policy",
            "The AWS account does not have a password policy defined",
            "Create a strong password policy for the account",
            "aws iam update-account-password-policy --minimum-password-length " + PASSWORD_POLICY_MIN_LENGTH +
            " --require-symbols --require-numbers --require-uppercase-characters " +
            "--require-lowercase-characters --password-reuse-prevention 24 --max-password-age 90"
        ));
    } catch (Exception e) {
        System.out.println("Could not check password policy: " + e.getMessage());
    }
}

    // Helper method to get the account ID
    private String getAccountId() {
        try {
            GetUserResponse userResp = iamClient.getUser();
            String userArn = userResp.user().arn();
            
            // ARN format: arn:aws:iam::ACCOUNT-ID:user/username
            Pattern pattern = Pattern.compile("arn:aws:iam::(\\d+):.*");
            Matcher matcher = pattern.matcher(userArn);
            
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            System.out.println("Could not determine account ID: " + e.getMessage());
        }
        
        return "unknown-account-id";
    }

    public List<SecurityIssue> getIssuesBySeverity(SecuritySeverity severity) {
        List<SecurityIssue> filteredIssues = new ArrayList<>();
        for (SecurityIssue issue : issues) {
            if (issue.getSeverity() == severity) {
                filteredIssues.add(issue);
            }
        }
        return filteredIssues;
    }
    
    public void close() {
        iamClient.close();
    }
}