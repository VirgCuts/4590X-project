package com.carter.awsvalidator;

import software.amazon.awssdk.regions.Region;

public class Main {
    public static void main(String[] args) {
        Region region = Region.US_EAST_2; // Update as needed

        // S3 scan
        S3BucketScanner s3Scanner = new S3BucketScanner(region);
        s3Scanner.scanBuckets();
        s3Scanner.close();

        // IAM scan
        IAMRoleScanner iamScanner = new IAMRoleScanner();
        iamScanner.scanRoles();
        iamScanner.close();

        // EC2 scan
        EC2SecurityGroupScanner ec2Scanner = new EC2SecurityGroupScanner(region);
        ec2Scanner.scanSecurityGroups();
        ec2Scanner.close();
    }
}
