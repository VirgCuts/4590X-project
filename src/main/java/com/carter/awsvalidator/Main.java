package com.carter.awsvalidator;

import java.util.ArrayList;
import java.util.List;

import software.amazon.awssdk.regions.Region;

public class Main {
    public static void main(String[] args) {
        Region region = Region.US_EAST_2; // Update as needed

        // S3 scan
        S3BucketScanner s3Scanner = new S3BucketScanner(region);
        s3Scanner.scanBuckets();
        // IAM scan
        IAMRoleScanner iamScanner = new IAMRoleScanner();
        iamScanner.scanRoles();
        // EC2 scan
        EC2SecurityGroupScanner ec2Scanner = new EC2SecurityGroupScanner(region);
        ec2Scanner.scanSecurityGroups();
        //this is all just terminal printout when starting, all of this gets fed to the assistant through allissues
        s3Scanner.printAllIssuesBySeverity();
        s3Scanner.printSummary();
        iamScanner.printAllIssuesBySeverity();
        iamScanner.printSummary();
        ec2Scanner.printAllIssuesBySeverity();
        ec2Scanner.printSummary();
        
        List<SecurityIssue> allIssues = new ArrayList<>();
        allIssues.addAll(s3Scanner.getIssues());
        allIssues.addAll(iamScanner.getIssues());
        allIssues.addAll(ec2Scanner.getIssues());

        SecurityAssistant assistant = new SecurityAssistant(allIssues);
        assistant.startSession();
        
        s3Scanner.close();
        iamScanner.close();
        ec2Scanner.close();
        
    }
}
