package com.carter.awsvalidator;

import java.util.List;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyRequest;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyResponse;
import software.amazon.awssdk.services.s3.model.GetPublicAccessBlockRequest;
import software.amazon.awssdk.services.s3.model.GetPublicAccessBlockResponse;
import software.amazon.awssdk.services.s3.model.PublicAccessBlockConfiguration;
import software.amazon.awssdk.services.s3.model.S3Exception;

public class S3BucketScanner {
    private final S3Client s3;

    public S3BucketScanner(Region region) {
        this.s3 = S3Client.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    public void scanBuckets() {
        System.out.println("🔍 Scanning S3 Buckets for public access...");

        List<Bucket> buckets = s3.listBuckets().buckets();

        for (Bucket bucket : buckets) {
            String bucketName = bucket.name();
            System.out.println("\n📁 Bucket: " + bucketName);

            checkPublicAccessBlock(bucketName);
            checkBucketPolicy(bucketName);
        }
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
                System.out.println("✅ Public Access Block is fully enabled.");
            } else {
                System.out.println("⚠️  Some public access settings are NOT blocked.");
            }

        } catch (S3Exception e) {
            System.out.println("⚠️  Could not retrieve Public Access Block config: " + e.awsErrorDetails().errorMessage());
        }
    }

    private void checkBucketPolicy(String bucketName) {
        try {
            GetBucketPolicyResponse policyResp = s3.getBucketPolicy(GetBucketPolicyRequest.builder()
                    .bucket(bucketName)
                    .build());

            String policyText = policyResp.policy();

            if (policyText.contains("\"Effect\":\"Allow\"") && policyText.contains("\"Principal\":\"*\"")) {
                System.out.println("❌ Bucket policy allows public access!");
            } else {
                System.out.println("✅ Bucket policy does not allow public access.");
            }
        } catch (S3Exception e) {
            if (e.awsErrorDetails().errorCode().equals("NoSuchBucketPolicy")) {
                System.out.println("✅ No bucket policy found (default: private).");
            } else {
                System.out.println("⚠️  Could not retrieve bucket policy: " + e.awsErrorDetails().errorMessage());
            }
        }
    }

    public void close() {
        s3.close();
    }
}
