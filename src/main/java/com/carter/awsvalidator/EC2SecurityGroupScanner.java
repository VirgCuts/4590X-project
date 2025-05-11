package com.carter.awsvalidator;

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

    public EC2SecurityGroupScanner(Region region) {
        this.ec2 = Ec2Client.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    public void scanSecurityGroups() {
        System.out.println("🔍 Scanning EC2 Security Groups for misconfigurations...");

        DescribeSecurityGroupsResponse response = ec2.describeSecurityGroups();
        List<SecurityGroup> groups = response.securityGroups();

        for (SecurityGroup group : groups) {
            System.out.println("\n🛡️ Security Group: " + group.groupName() + " (" + group.groupId() + ")");
            checkRules("Inbound", group.ipPermissions());
            checkRules("Outbound", group.ipPermissionsEgress());
        }
    }

    private void checkRules(String direction, List<IpPermission> permissions) {
        if (permissions.isEmpty()) {
            System.out.println("ℹ️  No " + direction.toLowerCase() + " rules defined.");
            return;
        }

        for (IpPermission perm : permissions) {
            int fromPort = perm.fromPort() != null ? perm.fromPort() : -1;
            int toPort = perm.toPort() != null ? perm.toPort() : -1;
            String protocol = perm.ipProtocol();

            // Check IPv4 ranges
            for (IpRange range : perm.ipRanges()) {
                String cidr = range.cidrIp();
                evaluateRule(direction, fromPort, toPort, protocol, cidr);
            }

            // Check IPv6 ranges
            for (Ipv6Range range : perm.ipv6Ranges()) {
                String cidr = range.cidrIpv6();
                evaluateRule(direction, fromPort, toPort, protocol, cidr);
            }
        }
    }

    private void evaluateRule(String direction, int fromPort, int toPort, String protocol, String cidr) {
        boolean isOpen = cidr.equals("0.0.0.0/0") || cidr.equals("::/0");
        String range = (fromPort == toPort) ? String.valueOf(fromPort) : fromPort + "-" + toPort;

        if (isOpen) {
            if (fromPort == 22 || toPort == 22) {
                System.out.printf("❌ [%s] CRITICAL: SSH (22) open to the world (%s)\n", direction, cidr);
            } else if (fromPort == 3389 || toPort == 3389) {
                System.out.printf("❌ [%s] CRITICAL: RDP (3389) open to the world (%s)\n", direction, cidr);
            } else if (fromPort == 0 && toPort == 65535) {
                System.out.printf("❌ [%s] CRITICAL: ALL ports open to the world (%s)\n", direction, cidr);
            } else {
                System.out.printf("⚠️  [%s] WARNING: Port %s open to the world (%s)\n", direction, range, cidr);
            }
        } else {
            System.out.printf("✅ [%s] INFO: Port %s restricted to %s\n", direction, range, cidr);
        }
    }

    public void close() {
        ec2.close();
    }
}
