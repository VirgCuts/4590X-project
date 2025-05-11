package com.carter.awsvalidator;

public class SecurityIssue {
    private final SecuritySeverity severity;
    private final String title;
    private final String description;
    private final String recommendation;
    private final String remediationCommand;

    public SecurityIssue(SecuritySeverity severity, String title, String description, 
                        String recommendation, String remediationCommand) {
        this.severity = severity;
        this.title = title;
        this.description = description;
        this.recommendation = recommendation;
        this.remediationCommand = remediationCommand;
    }

    // Getters
    public SecuritySeverity getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public String getRemediationCommand() {
        return remediationCommand;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s", severity, title, description);
    }
}