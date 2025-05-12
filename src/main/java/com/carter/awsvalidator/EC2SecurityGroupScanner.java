package com.carter.awsvalidator;

import java.util.ArrayList;
import java.util.List;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsResponse;
import software.amazon.awssdk.services.ec2.model.IpPermission;
import software.amazon.awssdk.services.ec2.model.IpRange;
import software.amazon.awssdk.services.ec2.model.Ipv6Range;
import software.amazon.awssdk.services.ec2.model.SecurityGroup;

public class EC2SecurityGroupScanner {
    private final Ec2Client ec2;
    private final List<SecurityIssue> issues = new ArrayList<>();

    private static final String RESET = "\u001B[0m";
    private static final String CYAN = "\u001B[36m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String ORANGE = "\u001B[38;5;208m";

    public EC2SecurityGroupScanner(Region region) {
        this.ec2 = Ec2Client.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }
    
    public List<SecurityIssue> scanSecurityGroups() {
        System.out.println(CYAN + "Scanning EC2 Security Groups for misconfigurations..." + RESET);
        issues.clear();

        DescribeSecurityGroupsResponse response = ec2.describeSecurityGroups();
        List<SecurityGroup> groups = response.securityGroups();

        for (SecurityGroup group : groups) {
            System.out.println("\nSecurity Group: " + group.groupName() + " (" + group.groupId() + ")");
            checkRules("Inbound", group.ipPermissions(), group);
            checkRules("Outbound", group.ipPermissionsEgress(), group);
        }

        return issues;
    }
    public void printAllIssuesBySeverity() {
    if (issues.isEmpty()) {
        System.out.println(GREEN + "No security issues found." + RESET);
        return;
    }

    System.out.println(CYAN+"\n### EC2GROUP SECURITY ISSUES BY SEVERITY ###"+RESET);

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
        


        System.out.println("\n### EC2GROUP SCAN SUMMARY ###");
        System.out.println("---------------------------");
        System.out.println(RED + " CRITICAL: " + criticalCount + RESET);
        System.out.println(ORANGE + " HIGH:     " + highCount+ RESET);
        System.out.println(YELLOW +" MEDIUM:   " + mediumCount+ RESET);
        System.out.println(GREEN + " LOW:      " + lowCount+ RESET);
        System.out.println("---------------------------");
        System.out.println("TOTAL:     " + issues.size());
    }
    private void checkRules(String direction, List<IpPermission> permissions, SecurityGroup group) {
        if (permissions.isEmpty()) {
            System.out.println("ℹNo " + direction.toLowerCase() + " rules defined.");
            return;
        }

        for (IpPermission perm : permissions) {
            int fromPort = perm.fromPort() != null ? perm.fromPort() : -1;
            int toPort = perm.toPort() != null ? perm.toPort() : -1;
            String protocol = perm.ipProtocol();

            // Check IPv4 ranges
            for (IpRange range : perm.ipRanges()) {
                String cidr = range.cidrIp();
                evaluateRule(direction, fromPort, toPort, protocol, cidr, group);
            }

            // Check IPv6 ranges
            for (Ipv6Range range : perm.ipv6Ranges()) {
                String cidr = range.cidrIpv6();
                evaluateRule(direction, fromPort, toPort, protocol, cidr, group);
            }
        }
    }

    private void evaluateRule(String direction, int fromPort, int toPort, String protocol, 
                             String cidr, SecurityGroup group) {
        boolean isOpen = cidr.equals("0.0.0.0/0") || cidr.equals("::/0");
        String range = (fromPort == toPort) ? String.valueOf(fromPort) : fromPort + "-" + toPort;
        String groupInfo = group.groupName() + " (" + group.groupId() + ")";
        
        if (isOpen) {
            if (fromPort == 22 || toPort == 22) {
                SecurityIssue issue = new SecurityIssue(
                    SecuritySeverity.CRITICAL,
                    "SSH Open to World",
                    String.format("%s rule in Security Group %s allows SSH (port 22) access from %s", 
                                 direction, groupInfo, cidr),
                    "Restrict SSH access to specific IP addresses or CIDR ranges",
                    String.format("aws ec2 revoke-security-group-%s-permission --group-id %s --protocol %s --port 22 --cidr %s", 
                                 direction.toLowerCase(), group.groupId(), protocol, cidr)
                );
                issues.add(issue);
            } else if (fromPort == 3389 || toPort == 3389) {
                SecurityIssue issue = new SecurityIssue(
                    SecuritySeverity.CRITICAL,
                    "RDP Open to World",
                    String.format("%s rule in Security Group %s allows RDP (port 3389) access from %s", 
                                 direction, groupInfo, cidr),
                    "Restrict RDP access to specific IP addresses or CIDR ranges",
                    String.format("aws ec2 revoke-security-group-%s-permission --group-id %s --protocol %s --port 3389 --cidr %s", 
                                 direction.toLowerCase(), group.groupId(), protocol, cidr)
                );
                issues.add(issue);
            } else if (fromPort == 0 && toPort == 65535) {
                SecurityIssue issue = new SecurityIssue(
                    SecuritySeverity.CRITICAL,
                    "All Ports Open to World",
                    String.format("%s rule in Security Group %s allows ALL ports access from %s", 
                                 direction, groupInfo, cidr),
                    "Restrict access to specific ports and IP addresses",
                    String.format("aws ec2 revoke-security-group-%s-permission --group-id %s --protocol %s --port all --cidr %s", 
                                 direction.toLowerCase(), group.groupId(), protocol, cidr)
                );
                issues.add(issue);
            } else {
                SecuritySeverity severity = isHighRiskPort(fromPort, toPort) ? 
                    SecuritySeverity.HIGH : SecuritySeverity.MEDIUM;
                
                SecurityIssue issue = new SecurityIssue(
                    severity,
                    "Port Open to World",
                    String.format("%s rule in Security Group %s allows port %s access from %s", 
                                 direction, groupInfo, range, cidr),
                    "Restrict access to specific IP addresses or CIDR ranges",
                    String.format("aws ec2 revoke-security-group-%s-permission --group-id %s --protocol %s --port %s --cidr %s", 
                                 direction.toLowerCase(), group.groupId(), protocol, range, cidr)
                );
                issues.add(issue);
            }
        } else {
            SecurityIssue issue = new SecurityIssue(
                SecuritySeverity.LOW,
                "Restricted Port Access",
                String.format("%s rule in Security Group %s allows port %s access from %s", 
                             direction, groupInfo, range, cidr),
                "No action needed",
                ""
            );
            issues.add(issue);
        }
    }
    
    private boolean isHighRiskPort(int fromPort, int toPort) {
        // Define ports that are considered high risk when exposed to the world
        int[] highRiskPorts = {
            21,    // FTP
            23,    // Telnet
            1433,  // MS SQL
            1521,  // Oracle
            3306,  // MySQL
            5432,  // PostgreSQL
            27017, // MongoDB
            6379,  // Redis
            9200   // Elasticsearch
        };
        
        for (int port : highRiskPorts) {
            if ((fromPort <= port && port <= toPort) || (fromPort == port) || (toPort == port)) {
                return true;
            }
        }
        return false;
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
        ec2.close();
    }
}