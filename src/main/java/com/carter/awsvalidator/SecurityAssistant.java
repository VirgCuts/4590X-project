package com.carter.awsvalidator;

import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

/**
 * AWS Security Assistant - Helps users understand and fix security issues
 * in their AWS environment.
 */
public class SecurityAssistant {
    private final List<SecurityIssue> securityIssues;
    private final Scanner scanner;
    
    private static final String RESET = "\u001B[0m";
    private static final String CYAN = "\u001B[36m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String ORANGE = "\u001B[38;5;208m";

    public SecurityAssistant(List<SecurityIssue> securityIssues) {
        this.securityIssues = securityIssues;
        this.scanner = new Scanner(System.in);
    }
    
    /**
     * Start the interactive assistant session
     */
    public void startSession() {
        System.out.println("==========================================");
        System.out.println(" AWS Security Validation Assistant ");
        System.out.println("==========================================");
        
        if (securityIssues.isEmpty()) {
            System.out.println("Great news! No security issues were found in your AWS environment.");
            return;
        }
        
        System.out.println("\nI found " + securityIssues.size() + " security issues in your AWS environment.");
        summarizeIssuesBySeverity();
        
        boolean exit = false;
        while (!exit) {
            showMainMenu();
            String choice = scanner.nextLine();
            
            switch (choice) {
                case "1":
                    listAllIssues();
                    break;
                case "2":
                    viewIssuesByCategory();
                    break;
                case "3":
                    guideThroughRemediation();
                    break;
                case "4":
                    explainSecurityConcepts();
                    break;
                case "5":
                    exit = true;
                    break;
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
        
        System.out.println("Thank you for using the AWS Security Validation Assistant!");
    }
    
    private void summarizeIssuesBySeverity() {
        long criticalCount = securityIssues.stream()
                .filter(issue -> issue.getSeverity() == SecuritySeverity.CRITICAL)
                .count();
        
        long highCount = securityIssues.stream()
                .filter(issue -> issue.getSeverity() == SecuritySeverity.HIGH)
                .count();
        
        long mediumCount = securityIssues.stream()
                .filter(issue -> issue.getSeverity() == SecuritySeverity.MEDIUM)
                .count();
        
        long lowCount = securityIssues.stream()
                .filter(issue -> issue.getSeverity() == SecuritySeverity.LOW)
                .count();
        
        System.out.println("Summary of issues:");
        System.out.println(RED+"CRITICAL: " + criticalCount+RESET);
        System.out.println(ORANGE+"HIGH: " + highCount+RESET);
        System.out.println(YELLOW+"MEDIUM: " + mediumCount+RESET);
        System.out.println(GREEN+"LOW: " + lowCount+RESET);
    }
    
    private void showMainMenu() {
        System.out.println("\nWhat would you like to do?");
        System.out.println("1. List all security issues");
        System.out.println("2. View issues by severity");
        System.out.println("3. Get guided remediation help");
        System.out.println("4. Learn about AWS security concepts");
        System.out.println("5. Exit");
        System.out.print("> ");
    }
    
    private void listAllIssues() {
        System.out.println("\n=== All Security Issues ===");
        for (int i = 0; i < securityIssues.size(); i++) {
            SecurityIssue issue = securityIssues.get(i);
            System.out.printf("%d. %s %s: %s%n", 
                    i + 1, 
                    getSeveritySymbol(issue.getSeverity()),
                    issue.getTitle(),
                    issue.getDescription());
        }
        
        System.out.println("\nEnter an issue number to see more details, or 'b' to go back:");
        String input = scanner.nextLine();
        
        if (!input.equalsIgnoreCase("b")) {
            try {
                int issueIndex = Integer.parseInt(input) - 1;
                if (issueIndex >= 0 && issueIndex < securityIssues.size()) {
                    showIssueDetails(securityIssues.get(issueIndex));
                } else {
                    System.out.println("Invalid issue number.");
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid input.");
            }
        }
    }
    
    private void viewIssuesByCategory() {
        System.out.println("\nSelect severity level to view:");
        System.out.println(RED+"1. CRITICAL"+RESET);
        System.out.println(ORANGE+"2. HIGH"+RESET);
        System.out.println(YELLOW+"3. MEDIUM"+RESET);
        System.out.println(GREEN+"4. LOW"+RESET);
        System.out.println(CYAN+"5. Back to main menu"+RESET);
        System.out.print("> ");
        
        String choice = scanner.nextLine();
        SecuritySeverity selectedSeverity;
        
        switch (choice) {
            case "1":
                selectedSeverity = SecuritySeverity.CRITICAL;
                break;
            case "2":
                selectedSeverity = SecuritySeverity.HIGH;
                break;
            case "3":
                selectedSeverity = SecuritySeverity.MEDIUM;
                break;
            case "4":
                selectedSeverity = SecuritySeverity.LOW;
                break;
            case "5":
                return;
            default:
                System.out.println("Invalid option.");
                return;
        }
        
        List<SecurityIssue> filteredIssues = securityIssues.stream()
                .filter(issue -> issue.getSeverity() == selectedSeverity)
                .collect(Collectors.toList());
        
        if (filteredIssues.isEmpty()) {
            System.out.println("No issues found with " + selectedSeverity + " severity.");
            return;
        }
        
        System.out.println("\n=== " + selectedSeverity + " Severity Issues ===");
        for (int i = 0; i < filteredIssues.size(); i++) {
            SecurityIssue issue = filteredIssues.get(i);
            System.out.printf("%d. %s: %s%n", 
                    i + 1, 
                    issue.getTitle(),
                    issue.getDescription());
        }
        
        System.out.println("\nEnter an issue number to see more details, or 'b' to go back:");
        String input = scanner.nextLine();
        
        if (!input.equalsIgnoreCase("b")) {
            try {
                int issueIndex = Integer.parseInt(input) - 1;
                if (issueIndex >= 0 && issueIndex < filteredIssues.size()) {
                    showIssueDetails(filteredIssues.get(issueIndex));
                } else {
                    System.out.println("Invalid issue number.");
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid input.");
            }
        }
    }
    
    private void guideThroughRemediation() {
        if (securityIssues.isEmpty()) {
            System.out.println("No security issues to remediate.");
            return;
        }
        
        System.out.println("\nLet's work through fixing your security issues.");
        
        // Filter CRITICAL severity issues first
        List<SecurityIssue> criticalSeverityIssues = securityIssues.stream()
                .filter(issue -> issue.getSeverity() == SecuritySeverity.CRITICAL)
                .collect(Collectors.toList());
        
        if (!criticalSeverityIssues.isEmpty()) {
            System.out.println("I recommend addressing CRITICAL severity issues first as they pose immediate risk:");
            guideIssueRemediation(criticalSeverityIssues);
            return;
        }
        
        // Then check HIGH severity issues
        System.out.println("Great! You don't have any CRITICAL severity issues.");
        System.out.println("Let's check for HIGH severity issues.");
        
        List<SecurityIssue> highSeverityIssues = securityIssues.stream()
                .filter(issue -> issue.getSeverity() == SecuritySeverity.HIGH)
                .collect(Collectors.toList());
        
        if (highSeverityIssues.isEmpty()) {
            System.out.println("Great! You don't have any HIGH severity issues either.");
            
            // Then suggest MEDIUM issues
            List<SecurityIssue> mediumSeverityIssues = securityIssues.stream()
                    .filter(issue -> issue.getSeverity() == SecuritySeverity.MEDIUM)
                    .collect(Collectors.toList());
            
            if (!mediumSeverityIssues.isEmpty()) {
                System.out.println("Let's address your MEDIUM severity issues:");
                guideIssueRemediation(mediumSeverityIssues);
            } else {
                System.out.println("You only have LOW severity issues. Would you like to address them? (y/n)");
                String answer = scanner.nextLine();
                if (answer.equalsIgnoreCase("y")) {
                    List<SecurityIssue> lowSeverityIssues = securityIssues.stream()
                            .filter(issue -> issue.getSeverity() == SecuritySeverity.LOW)
                            .collect(Collectors.toList());
                    guideIssueRemediation(lowSeverityIssues);
                }
            }
        } else {
            System.out.println("Let's fix your HIGH severity issues:");
            guideIssueRemediation(highSeverityIssues);
        }
    }
    
    private void guideIssueRemediation(List<SecurityIssue> issues) {
        for (int i = 0; i < issues.size(); i++) {
            SecurityIssue issue = issues.get(i);
            System.out.printf("\n=== Issue %d/%d: %s ===\n", 
                    i + 1, issues.size(), issue.getTitle());
            System.out.println("Description: " + issue.getDescription());
            System.out.println("\nRecommended action: " + issue.getRecommendation());
            
            if (issue.getRemediationCommand() != null && !issue.getRemediationCommand().isEmpty()) {
                System.out.println("\nYou can fix this issue by running the following command:");
                System.out.println("    " + issue.getRemediationCommand());
                
                // For future implementation: option to execute the command automatically
                System.out.println("\nWould you like me to help you fix this? (future feature)");
            }
            
            System.out.println("\nPress Enter when you've addressed this issue or type 'skip' to come back to it later.");
            String input = scanner.nextLine();
            
            if (input.equalsIgnoreCase("skip")) {
                System.out.println("Skipped for now. We'll come back to this issue later.");
            } else {
                System.out.println("Great! Let's move on to the next issue.");
            }
        }
    }
    
    private void explainSecurityConcepts() {
        System.out.println(CYAN+"\n=== AWS Security Concepts ==="+RESET);
        System.out.println("What would you like to learn about?");
        System.out.println("1. S3 Bucket Security");
        System.out.println("2. IAM Best Practices");
        System.out.println("3. Security Groups & Network ACLs");
        System.out.println("4. AWS Encryption Options");
        System.out.println("5. Back to main menu");
        System.out.print("> ");
        
        String choice = scanner.nextLine();
        
        switch (choice) {
            case "1":
                explainS3Security();
                break;
            case "2":
                explainIAMBestPractices();
                break;
            case "3":
                explainNetworkSecurity();
                break;
            case "4":
                explainEncryptionOptions();
                break;
            case "5":
                return;
            default:
                System.out.println("Invalid option.");
                return;
        }
    }
    
    private void showIssueDetails(SecurityIssue issue) {
        System.out.println("\n=== Issue Details ===");
        System.out.println("Severity: " + getSeveritySymbol(issue.getSeverity()) + " " + issue.getSeverity());
        System.out.println("Title: " + issue.getTitle());
        System.out.println("Description: " + issue.getDescription());
        System.out.println("\nRecommendation:");
        System.out.println(issue.getRecommendation());
        
        if (issue.getRemediationCommand() != null && !issue.getRemediationCommand().isEmpty()) {
            System.out.println("\nRemediation Command:");
            System.out.println(issue.getRemediationCommand());
        }
        
        System.out.println("\nPress Enter to go back");
        scanner.nextLine();
    }
    
    private String getSeveritySymbol(SecuritySeverity severity) {
        switch (severity) {
            case CRITICAL:
                return RED + "#" +  RESET;
            case HIGH:
                return  ORANGE + "#" +  RESET;
            case MEDIUM:
                return YELLOW + "#" +  RESET;
            case LOW:
                return GREEN + "#" +  RESET;
            default:
                return CYAN + "#" +  RESET;
        }
    }
    
    // Security concept explanations
    private void explainS3Security() {
        System.out.println("\n=== S3 Bucket Security ===");
        System.out.println("S3 (Simple Storage Service) security is critical because misconfigured S3 buckets " +
                "are one of the most common causes of data breaches.");
        
        System.out.println("\nKey S3 security best practices:");
        System.out.println("1. Block Public Access - Use the S3 Block Public Access feature at the account level");
        System.out.println("2. Bucket Policies - Carefully control who can access your data with bucket policies");
        System.out.println("3. ACLs - Although AWS recommends using bucket policies, ACLs can provide additional control");
        System.out.println("4. Encryption - Enable encryption at rest for sensitive data (SSE-S3, SSE-KMS, or SSE-C)");
        System.out.println("5. Versioning - Enable versioning to protect against accidental deletions");
        System.out.println("6. Logging - Enable access logging to track who is accessing your data");
        
        System.out.println("\nPress Enter to go back");
        scanner.nextLine();
    }
    
    private void explainIAMBestPractices() {
        System.out.println("\n=== IAM Best Practices ===");
        System.out.println("Identity and Access Management (IAM) is fundamental to AWS security, " +
                "controlling who can access your resources and what they can do.");
        
        System.out.println("\nKey IAM best practices:");
        System.out.println("1. Least Privilege - Grant only the permissions needed to perform a task");
        System.out.println("2. Use IAM Roles - For services and EC2 instances instead of access keys");
        System.out.println("3. MFA - Enable Multi-Factor Authentication for all users, especially the root account");
        System.out.println("4. Regular Audits - Review permissions regularly to remove unnecessary access");
        System.out.println("5. Strong Password Policy - Enforce complex passwords and regular rotation");
        System.out.println("6. Group-Based Access - Use IAM groups to manage permissions for multiple users");
        
        System.out.println("\nPress Enter to go back");
        scanner.nextLine();
    }
    
    private void explainNetworkSecurity() {
        System.out.println("\n=== Security Groups & Network ACLs ===");
        System.out.println("AWS network security controls traffic to and from your resources.");
        
        System.out.println("\nSecurity Groups:");
        System.out.println("- Act as a virtual firewall for EC2 instances");
        System.out.println("- Stateful: Return traffic is automatically allowed");
        System.out.println("- Can specify allow rules but not deny rules");
        System.out.println("- Applied at the instance level");
        
        System.out.println("\nNetwork ACLs:");
        System.out.println("- Acts as a firewall for subnets");
        System.out.println("- Stateless: Return traffic must be explicitly allowed");
        System.out.println("- Can specify both allow and deny rules");
        System.out.println("- Applied at the subnet level");
        
        System.out.println("\nBest Practices:");
        System.out.println("1. Default to Deny - Only open necessary ports");
        System.out.println("2. Least Access - Restrict source IPs to known addresses when possible");
        System.out.println("3. Regular Review - Audit rules to remove outdated permissions");
        
        System.out.println("\nPress Enter to go back");
        scanner.nextLine();
    }
    
    private void explainEncryptionOptions() {
        System.out.println("\n=== AWS Encryption Options ===");
        System.out.println("AWS offers various encryption mechanisms to protect your data.");
        
        System.out.println("\nEncryption Types:");
        System.out.println("1. Encryption at Rest - Data stored on disk");
        System.out.println("   - S3: SSE-S3, SSE-KMS, SSE-C, client-side encryption");
        System.out.println("   - EBS: AWS managed keys or custom KMS keys");
        System.out.println("   - RDS: Encryption with AWS KMS");
        
        System.out.println("\n2. Encryption in Transit - Data moving across the network");
        System.out.println("   - TLS for API communication");
        System.out.println("   - VPN for network connections");
        System.out.println("   - Certificate Manager for managing SSL/TLS certificates");
        
        System.out.println("\nKey Management:");
        System.out.println("- AWS KMS: Managed key service for creating and controlling encryption keys");
        System.out.println("- CloudHSM: Hardware-based key storage for regulatory compliance");
        
        System.out.println("\nPress Enter to go back");
        scanner.nextLine();
    }

}