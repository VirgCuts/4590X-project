package com.carter.awsvalidator;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.bedrockruntime.BedrockRuntimeClient;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelRequest;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelResponse;
import software.amazon.awssdk.core.SdkBytes;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.HashMap;
import java.util.Map;

/**
 * Class that handles integration with AWS Bedrock for AI assistance
 */
public class BedrockAssistant {
    private final BedrockRuntimeClient bedrockClient;
    private final ObjectMapper objectMapper;
    private final String defaultModelId = "amazon.nova-micro-v1:0"; // Change to appropriate model ID
    
    public BedrockAssistant() {
        this.bedrockClient = BedrockRuntimeClient.builder()
                .region(Region.US_EAST_1) // Update with your preferred region
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Get AI-generated explanation for a specific security issue
     * @param issue The security issue to explain
     * @return AI-generated explanation
     */
    public String explainSecurityIssue(SecurityIssue issue) {
        try {
            // Create prompt for the AI model
            String prompt = createPromptForIssueExplanation(issue);
            
            // Get response from Bedrock
            String response = invokeBedrockModel(prompt);
            
            return response;
        } catch (Exception e) {
            System.err.println("Error getting AI explanation: " + e.getMessage());
            return "Unable to generate AI explanation: " + e.getMessage();
        }
    }
    
    /**
     * Get AI-generated remediation steps for a security issue
     * @param issue The security issue to provide remediation for
     * @return AI-generated remediation steps
     */
    public String getRemediationSteps(SecurityIssue issue) {
        try {
            // Create prompt for the AI model
            String prompt = createPromptForRemediation(issue);
            
            // Get response from Bedrock
            String response = invokeBedrockModel(prompt);
            
            return response;
        } catch (Exception e) {
            System.err.println("Error getting remediation steps: " + e.getMessage());
            return "Unable to generate remediation steps: " + e.getMessage();
        }
    }
    
    /**
     * Answer user's question about AWS security
     * @param question The user's question
     * @return AI-generated answer
     */
    public String answerSecurityQuestion(String question) {
        try {
            // Create prompt for the AI model
            String prompt = createPromptForQuestion(question);
            
            // Get response from Bedrock
            String response = invokeBedrockModel(prompt);
            
            return response;
        } catch (Exception e) {
            System.err.println("Error answering question: " + e.getMessage());
            return "I'm unable to answer this question right now: " + e.getMessage();
        }
    }
    
    /**
     * Create a prompt for explaining a security issue
     */
    private String createPromptForIssueExplanation(SecurityIssue issue) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Human: I'm a non-security expert AWS user. Please explain this AWS security issue in simple terms:\n\n");
        prompt.append("Issue: ").append(issue.getTitle()).append("\n");
        prompt.append("Description: ").append(issue.getDescription()).append("\n\n");
        prompt.append("Please explain:\n");
        prompt.append("1. Why this is a security concern\n");
        prompt.append("2. What could happen if it's not addressed\n");
        prompt.append("3. The basic concept behind this security principle\n\n");
        prompt.append("Keep your explanation simple and jargon-free.\n\n");
        prompt.append("Assistant:");
        
        return prompt.toString();
    }
    
    /**
     * Create a prompt for remediation steps
     */
    private String createPromptForRemediation(SecurityIssue issue) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Human: I'm a non-security expert AWS user. I need help fixing this AWS security issue:\n\n");
        prompt.append("Issue: ").append(issue.getTitle()).append("\n");
        prompt.append("Description: ").append(issue.getDescription()).append("\n");
        if (issue.getRemediationCommand() != null && !issue.getRemediationCommand().isEmpty()) {
            prompt.append("Suggested command: ").append(issue.getRemediationCommand()).append("\n\n");
        }
        prompt.append("Please provide:\n");
        prompt.append("1. Step-by-step instructions to fix this issue\n");
        prompt.append("2. Explanation of what each step does\n");
        prompt.append("3. How to verify the issue is fixed\n\n");
        prompt.append("Keep your explanation simple and jargon-free.\n\n");
        prompt.append("Assistant:");
        
        return prompt.toString();
    }
    
    /**
     * Create a prompt for answering a general security question
     */
    private String createPromptForQuestion(String question) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Human: I'm a non-security expert AWS user. ").append(question).append("\n\n");
        prompt.append("Please explain this in simple terms, avoiding technical jargon where possible.\n\n");
        prompt.append("Assistant:");
        
        return prompt.toString();
    }
    private String invokeBedrockModel(String prompt) throws Exception {
    try {
        // Create the main request body
        ObjectNode requestBodyJson = objectMapper.createObjectNode();
        
        // Add inferenceConfig
        ObjectNode inferenceConfig = requestBodyJson.putObject("inferenceConfig");
        inferenceConfig.put("max_new_tokens", 1000);
        
        // Create messages array
        ArrayNode messagesArray = requestBodyJson.putArray("messages");
        
        // Create user message
        ObjectNode userMessage = objectMapper.createObjectNode();
        userMessage.put("role", "user");
        
        // Create content array for the message
        ArrayNode contentArray = objectMapper.createArrayNode();
        ObjectNode textContent = objectMapper.createObjectNode();
        textContent.put("text", prompt);
        contentArray.add(textContent);
        
        // Add content array to user message
        userMessage.set("content", contentArray);
        
        // Add user message to messages array
        messagesArray.add(userMessage);
        
        String requestBody = objectMapper.writeValueAsString(requestBodyJson);

        InvokeModelRequest request = InvokeModelRequest.builder()
                .modelId("amazon.nova-micro-v1:0")  // Using the specific model ID
                .contentType("application/json")
                .accept("application/json")
                .body(SdkBytes.fromUtf8String(requestBody))
                .build();

        InvokeModelResponse response = bedrockClient.invokeModel(request);
        //answer from aws
        String responseBody = response.body().asUtf8String();
        
        //we just want the text not the rest of the json
        ObjectNode responseJson = (ObjectNode) objectMapper.readTree(responseBody);
        String resultText = responseJson
                .path("output")
                .path("message")
                .path("content")
                .get(0)
                .path("text")
                .asText();
        // Return the raw response for debugging
        return "Response: " + resultText;
        
        /* Commented out for debugging
        ObjectNode responseJson = (ObjectNode) objectMapper.readTree(responseBody);
        return responseJson.path("messages").path(0).path("content").path(0).path("text").asText();
        */
    } catch (Exception e) {
        System.err.println("Error details: " + e.getMessage());
        e.printStackTrace();
        throw new Exception("Error invoking Bedrock model: " + e.getMessage(), e);
    }
}

}