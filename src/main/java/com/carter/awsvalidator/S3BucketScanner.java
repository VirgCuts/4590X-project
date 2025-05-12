package com.carter.awsvalidator;

import java.util.ArrayList;
import java.util.List;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.GetBucketEncryptionRequest;
import software.amazon.awssdk.services.s3.model.GetBucketEncryptionResponse;
import software.amazon.awssdk.services.s3.model.GetBucketLifecycleConfigurationRequest;
import software.amazon.awssdk.services.s3.model.GetBucketLifecycleConfigurationResponse;
import software.amazon.awssdk.services.s3.model.GetBucketLoggingRequest;
import software.amazon.awssdk.services.s3.model.GetBucketLoggingResponse;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyRequest;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyResponse;
import software.amazon.awssdk.services.s3.model.GetBucketReplicationRequest;
import software.amazon.awssdk.services.s3.model.GetBucketReplicationResponse;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningResponse;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclResponse;
import software.amazon.awssdk.services.s3.model.GetPublicAccessBlockRequest;
import software.amazon.awssdk.services.s3.model.GetPublicAccessBlockResponse;
import software.amazon.awssdk.services.s3.model.Grant;
import software.amazon.awssdk.services.s3.model.Grantee;
import software.amazon.awssdk.services.s3.model.LifecycleRule;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.PublicAccessBlockConfiguration;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.paginators.ListObjectsV2Iterable;


public class S3BucketScanner {
    private final S3Client s3;
    private final List<SecurityIssue> issues = new ArrayList<>();

    private static final String RESET = "\u001B[0m";
    private static final String CYAN = "\u001B[36m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String ORANGE = "\u001B[38;5;208m";

    public S3BucketScanner(Region region) {
        this.s3 = S3Client.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    public List<SecurityIssue> scanBuckets() {
        System.out.println(CYAN + "Scanning S3 Buckets for security issues..." + RESET);
        issues.clear();
        
        List<Bucket> buckets = s3.listBuckets().buckets();
        for (Bucket bucket : buckets) {
            String bucketName = bucket.name();
            System.out.println("\n📁 Bucket: " + bucketName);
            
            // Run all security checks for this bucket
            checkPublicAccessBlock(bucketName);
            checkBucketPolicy(bucketName);
            checkEncryption(bucketName);
            checkVersioning(bucketName);
            checkObjectPermissions(bucketName);
            checkLogging(bucketName);
            checkLifecycleRules(bucketName);
            checkCrossRegionReplication(bucketName);
            checkSecureTransport(bucketName);
        }

        return issues;
    }
    public void printAllIssuesBySeverity() {
    if (issues.isEmpty()) {
        System.out.println(GREEN + "No security issues found." + RESET);
        return;
    }

    System.out.println(CYAN+"\n### S3BUCKET SECURITY ISSUES BY SEVERITY ###"+RESET);

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

        System.out.println("\n### S3BUCKET SCAN SUMMARY ###");
        System.out.println("---------------------------");
        System.out.println(RED + " CRITICAL: " + criticalCount + RESET);
        System.out.println(ORANGE + " HIGH:     " + highCount+ RESET);
        System.out.println(YELLOW +" MEDIUM:   " + mediumCount+ RESET);
        System.out.println(GREEN + " LOW:      " + lowCount+ RESET);
        System.out.println("---------------------------");
        System.out.println("TOTAL:     " + issues.size());
    }

    private void checkPublicAccessBlock(String bucketName) {
        try {
            GetPublicAccessBlockResponse blockResp = s3.getPublicAccessBlock(GetPublicAccessBlockRequest.builder()
                    .bucket(bucketName)
                    .build());
            
            PublicAccessBlockConfiguration config = blockResp.publicAccessBlockConfiguration();
            boolean isBlocked = config.blockPublicAcls() &&
                                config.blockPublicPolicy() &&
                                config.ignorePublicAcls() &&
                                config.restrictPublicBuckets();
            
            if (isBlocked) {
                System.out.println("Public Access Block is fully enabled.");
            } else {
                System.out.println("Some public access settings are NOT blocked.");
                issues.add(new SecurityIssue(
                    SecuritySeverity.HIGH,
                    "Incomplete Public Access Block Settings",
                    "Bucket " + bucketName + " does not have all public access block settings enabled",
                    "Enable all four public access block settings to prevent accidental exposure",
                    "aws s3api put-public-access-block --bucket " + bucketName + 
                    " --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true," +
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ));
            }
        } catch (S3Exception e) {
            System.out.println("Could not retrieve Public Access Block config: " + e.awsErrorDetails().errorMessage());
            issues.add(new SecurityIssue(
                SecuritySeverity.HIGH,
                "Missing Public Access Block Configuration",
                "Bucket " + bucketName + " does not have public access block configuration set",
                "Set up public access block settings to restrict public access",
                "aws s3api put-public-access-block --bucket " + bucketName + 
                " --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true," +
                "BlockPublicPolicy=true,RestrictPublicBuckets=true"
            ));
        }
    }

    private void checkBucketPolicy(String bucketName) {
        try {
            GetBucketPolicyResponse policyResp = s3.getBucketPolicy(GetBucketPolicyRequest.builder()
                    .bucket(bucketName)
                    .build());
            
            String policyText = policyResp.policy();
            if (policyText.contains("\"Effect\":\"Allow\"") && policyText.contains("\"Principal\":\"*\"")) {
                System.out.println("Bucket policy allows public access!");
                issues.add(new SecurityIssue(
                    SecuritySeverity.CRITICAL,
                    "Public Bucket Policy",
                    "Bucket " + bucketName + " has a policy that allows public access",
                    "Modify the bucket policy to restrict access to authorized users only",
                    "Review the bucket policy with: aws s3api get-bucket-policy --bucket " + bucketName
                ));
            } else {
                System.out.println("Bucket policy does not allow public access.");
            }
        } catch (S3Exception e) {
            if (e.awsErrorDetails().errorCode().equals("NoSuchBucketPolicy")) {
                System.out.println("No bucket policy found (default: private).");
            } else {
                System.out.println("Could not retrieve bucket policy: " + e.awsErrorDetails().errorMessage());
            }
        }
    }

    private void checkEncryption(String bucketName) {
        try {
            GetBucketEncryptionResponse encResp = s3.getBucketEncryption(GetBucketEncryptionRequest.builder()
                    .bucket(bucketName)
                    .build());
            
            System.out.println("Default encryption is enabled.");
        } catch (S3Exception e) {
            if (e.awsErrorDetails().errorCode().equals("ServerSideEncryptionConfigurationNotFoundError")) {
                System.out.println("Default encryption is NOT enabled!");
                issues.add(new SecurityIssue(
                    SecuritySeverity.HIGH,
                    "Missing Default Encryption",
                    "Bucket " + bucketName + " does not have default encryption enabled",
                    "Enable default encryption to protect data at rest",
                    "aws s3api put-bucket-encryption --bucket " + bucketName + 
                    " --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":" +
                    "{\"SSEAlgorithm\":\"AES256\"}}]}'"
                ));
            } else {
                System.out.println("Could not check encryption settings: " + e.awsErrorDetails().errorMessage());
            }
        }
    }

    private void checkVersioning(String bucketName) {
        try {
            GetBucketVersioningResponse versionResp = s3.getBucketVersioning(GetBucketVersioningRequest.builder()
                    .bucket(bucketName)
                    .build());
            
            BucketVersioningStatus status = versionResp.status();
            if (status != BucketVersioningStatus.ENABLED) {
                System.out.println("Bucket versioning is not enabled.");
                issues.add(new SecurityIssue(
                    SecuritySeverity.MEDIUM,
                    "Versioning Not Enabled",
                    "Bucket " + bucketName + " does not have versioning enabled",
                    "Enable versioning to protect against accidental deletion and for data recovery",
                    "aws s3api put-bucket-versioning --bucket " + bucketName + " --versioning-configuration Status=Enabled"
                ));
            } else {
                System.out.println("Bucket versioning is enabled.");
            }
        } catch (S3Exception e) {
            System.out.println("Could not check versioning: " + e.awsErrorDetails().errorMessage());
        }
    }

    private void checkObjectPermissions(String bucketName) {
        try {
            // Sample a few objects (limit to first 100) to check for public ACLs
            int publicObjects = 0;
            ListObjectsV2Iterable objects = s3.listObjectsV2Paginator(ListObjectsV2Request.builder()
                    .bucket(bucketName)
                    .maxKeys(100)
                    .build());
            
            for (ListObjectsV2Response page : objects) {
                for (S3Object object : page.contents()) {
                    try {
                        GetObjectAclResponse aclResp = s3.getObjectAcl(GetObjectAclRequest.builder()
                                .bucket(bucketName)
                                .key(object.key())
                                .build());
                        
                        // Check for public access grants
                        for (Grant grant : aclResp.grants()) {
                            Grantee grantee = grant.grantee();
                            if (grantee.uri() != null && grantee.uri().contains("AllUsers")) {
                                publicObjects++;
                                break;
                            }
                        }
                    } catch (S3Exception e) {
                        // Skip if we can't check a specific object
                        continue;
                    }
                }
            }
            
            if (publicObjects > 0) {
                System.out.println("Found " + publicObjects + " objects with public ACLs!");
                issues.add(new SecurityIssue(
                    SecuritySeverity.CRITICAL,
                    "Public Object Permissions",
                    "Bucket " + bucketName + " contains " + publicObjects + " objects with public access permissions",
                    "Remove public access permissions from these objects",
                    "Use AWS Console or CLI to review and modify object ACLs"
                ));
            } else {
                System.out.println("No publicly accessible objects found (limited to first 100 objects).");
            }
        } catch (S3Exception e) {
            System.out.println("Could not check object permissions: " + e.awsErrorDetails().errorMessage());
        }
    }

    private void checkLogging(String bucketName) {
        try {
            GetBucketLoggingResponse loggingResp = s3.getBucketLogging(GetBucketLoggingRequest.builder()
                    .bucket(bucketName)
                    .build());
            
            if (loggingResp.loggingEnabled() == null) {
                System.out.println("Bucket logging is not enabled.");
                issues.add(new SecurityIssue(
                    SecuritySeverity.MEDIUM,
                    "Logging Not Enabled",
                    "Bucket " + bucketName + " does not have logging enabled",
                    "Enable logging to track access and changes to the bucket",
                    "aws s3api put-bucket-logging --bucket " + bucketName + 
                    " --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"log-bucket-name\"," +
                    "\"TargetPrefix\":\"" + bucketName + "/\"}}'"
                ));
            } else {
                System.out.println("Bucket logging is enabled.");
            }
        } catch (S3Exception e) {
            System.out.println("Could not check logging settings: " + e.awsErrorDetails().errorMessage());
        }
    }

    private void checkLifecycleRules(String bucketName) {
        try {
            GetBucketLifecycleConfigurationResponse lifecycleResp = s3.getBucketLifecycleConfiguration(
                    GetBucketLifecycleConfigurationRequest.builder()
                    .bucket(bucketName)
                    .build());
            
            List<LifecycleRule> rules = lifecycleResp.rules();
            if (rules == null || rules.isEmpty()) {
                System.out.println("No lifecycle rules defined.");
                issues.add(new SecurityIssue(
                    SecuritySeverity.LOW,
                    "Missing Lifecycle Rules",
                    "Bucket " + bucketName + " does not have any lifecycle rules configured",
                    "Configure lifecycle rules to manage object retention and deletion",
                    "Consider adding lifecycle rules through AWS Console or CLI"
                ));
            } else {
                System.out.println("Lifecycle rules are configured.");
            }
        } catch (S3Exception e) {
            if (e.awsErrorDetails().errorCode().equals("NoSuchLifecycleConfiguration")) {
                System.out.println("No lifecycle configuration.");
                issues.add(new SecurityIssue(
                    SecuritySeverity.LOW,
                    "Missing Lifecycle Configuration",
                    "Bucket " + bucketName + " does not have lifecycle configuration",
                    "Configure lifecycle rules to manage object retention and deletion",
                    "Consider adding lifecycle rules through AWS Console or CLI"
                ));
            } else {
                System.out.println("Could not check lifecycle configuration: " + e.awsErrorDetails().errorMessage());
            }
        }
    }

    private void checkCrossRegionReplication(String bucketName) {
        try {
            GetBucketReplicationResponse replResp = s3.getBucketReplication(GetBucketReplicationRequest.builder()
                    .bucket(bucketName)
                    .build());
            
            System.out.println("Cross-region replication is configured.");
        } catch (S3Exception e) {
            if (e.awsErrorDetails().errorCode().equals("ReplicationConfigurationNotFoundError")) {
                System.out.println("Cross-region replication not configured.");
                issues.add(new SecurityIssue(
                    SecuritySeverity.LOW,
                    "No Cross-Region Replication",
                    "Bucket " + bucketName + " does not have cross-region replication configured",
                    "Consider setting up cross-region replication for disaster recovery",
                    "Configure replication through AWS Console or CLI"
                ));
            } else {
                System.out.println("Could not check replication: " + e.awsErrorDetails().errorMessage());
            }
        }
    }

    private void checkSecureTransport(String bucketName) {
        try {
            GetBucketPolicyResponse policyResp = s3.getBucketPolicy(GetBucketPolicyRequest.builder()
                    .bucket(bucketName)
                    .build());
            
            String policyText = policyResp.policy();
            boolean hasSecureTransport = policyText.contains("aws:SecureTransport") && 
                                        policyText.contains("\"Bool\":{\"aws:SecureTransport\":\"false\"}") &&
                                        policyText.contains("\"Effect\":\"Deny\"");
            
            if (!hasSecureTransport) {
                System.out.println("No secure transport (HTTPS) policy enforced.");
                issues.add(new SecurityIssue(
                    SecuritySeverity.MEDIUM,
                    "HTTPS Not Enforced",
                    "Bucket " + bucketName + " does not enforce HTTPS-only access",
                    "Add a bucket policy to deny HTTP access",
                    "Add policy that denies access when SecureTransport is false"
                ));
            } else {
                System.out.println("HTTPS-only access is enforced.");
            }
        } catch (S3Exception e) {
            if (e.awsErrorDetails().errorCode().equals("NoSuchBucketPolicy")) {
                System.out.println("No secure transport (HTTPS) policy enforced (no bucket policy).");
                issues.add(new SecurityIssue(
                    SecuritySeverity.MEDIUM,
                    "HTTPS Not Enforced",
                    "Bucket " + bucketName + " does not enforce HTTPS-only access",
                    "Add a bucket policy to deny HTTP access",
                    "Add policy that denies access when SecureTransport is false"
                ));
            } else {
                System.out.println("Could not check HTTPS policy: " + e.awsErrorDetails().errorMessage());
            }
        }
    }
    public List<SecurityIssue> getIssues() {
        return issues;
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
        s3.close();
    }
}