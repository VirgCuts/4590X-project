Project Idea: AWS Secure Resource Validation with AI assistant 

    My proposal for the term project is an Interface for non-security AWS users to 
identify and fix common security misconfiguration on there pre-existing AWS resources. 
The tool will first scan a user’s AWS environment for any possible security 
risk/misconfigurations such as say a public S3 bucket or a IAM role with to many 
permissions and provide the user with recommendations to help enhance resource 
security. The plan is to have the assistant be able to explain the process of correcting these 
issues and even suggest best security practices for the user. Depending on how difficult the 
assistant is to implement there I have also had the thought of possibly allowing the 
assistant to make changes, however this would likely be very bare-bones if implemented.  
The end result is to mainly create a lightweight Validation tool that scans a user AWS 
environment, suggests security improvement changes, and is able to effectively 
communicate the need for these changes and how to fix them. The project will likely be 
near totally in java and will try to utilize AWS’s bedrock services however im not sure of how 
extensive the services is.