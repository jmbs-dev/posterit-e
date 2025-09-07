# Posterit-E: Backend Serverless

![alt text](https://img.shields.io/badge/build-passing-brightgreen)
![alt text](https://img.shields.io/badge/License-MIT-yellow.svg)

Official repository for the Posterit-E serverless backend, a secure, private, and open-source digital legacy platform.

---

## 📜 Project Overview

Posterit-E is a platform designed to allow users to store confidential information (such as passwords, cryptocurrency keys, documents, or personal notes) and ensure its controlled delivery to designated beneficiaries after an event that incapacitates the owner, such as death.

The system is based on a principle of minimal trust, where the platform never has access to the content of the user's secrets.

---

## ✨ Core Principles

- 🔐 **Zero-Knowledge Security:** The cryptographic design ensures the server acts as a "blind custodian." All encryption and decryption operations occur exclusively on the client side (in the owner's and beneficiary's browser). The server only stores and manages encrypted data blobs.
- 🛡️ **End-to-End Encryption (E2E):** Information is always transmitted and stored encrypted. Only the owner (when creating the secret) and the final beneficiary (when recovering it with the correct password) can access the plaintext content.
- 🚀 **Serverless Architecture on AWS:** To ensure scalability, cost efficiency, and a focus on business logic, the backend is built 100% with managed AWS services, mainly AWS Lambda, API Gateway, DynamoDB, and S3.
- 🌐 **Open Source:** Transparency is key to trust. As an open-source project, it allows public and independent auditing of its code and security protocols.

---

## 🏛️ Backend Architecture

This repository contains the source code and infrastructure-as-code (IaC) configuration for all backend functions. We use the **AWS Serverless Application Model (SAM)** to define and deploy resources.

The "brain" of the architecture is in the `template.yaml` file, which defines:

- **API Gateway:** The RESTful endpoints that expose functionality.
- **AWS Lambda:** The functions containing business logic.
- **DynamoDB:** The NoSQL table for storing metadata and states.
- **S3:** The bucket for storing encrypted secrets.
- **IAM Roles and Permissions:** Policies that ensure communication between services under the principle of least privilege.

---

## 📁 Repository Structure

The project follows a monorepo structure, where each Lambda function resides in its own directory to isolate dependencies and facilitate management.

```text
posterit-e-lambdas/
├── functions/
│   ├── store_secret_lambda/
│   │   ├── app.py             # Function logic
│   │   └── requirements.txt   # Python dependencies
│   ├── activation_lambda/
│   │   ├── app.py
│   │   └── requirements.txt
│   ├── cancellation_lambda/
│   │   ├── app.py
│   │   └── requirements.txt
│   └── release_lambda/
│       ├── app.py
│       └── requirements.txt
│
├── template.yaml              # AWS SAM template (Infrastructure as Code)
└── README.md                  # This file
```

---

## 🚀 Getting Started

Follow these steps to set up your development environment and deploy the backend to your own AWS account.

### Prerequisites

- An AWS account.
- Python 3.9 or higher.
- AWS CLI configured with your credentials.
- AWS SAM CLI installed.

### Build

The `sam build` command compiles the source code, downloads each Lambda function's dependencies, and prepares the artifacts for deployment.

```bash
# From the project's root directory
sam build
```

### Deploy

The `sam deploy --guided` command packages and deploys the infrastructure defined in `template.yaml`. If this is your first deployment, or if you want to customize resources, you can pass the required parameters:

First, export the ARN of your verified SES identity as an environment variable (this avoids exposing it in the repository):

```bash
export SES_IDENTITY_ARN=arn:aws:ses:REGION:ACCOUNT:identity/your-domain-or-email.com
```

Then run the deployment using the variable:

```bash
sam deploy --guided \
  --parameter-overrides \
  PosteritETableName=PosteritETable \
  PosteritES3BucketName=posterite \
  SESIdentityArn=$SES_IDENTITY_ARN
```

- `PosteritETableName`: Name of the DynamoDB table for secrets.
- `PosteritES3BucketName`: Name of the S3 bucket for encrypted secrets.
- `SESIdentityArn`: ARN of the verified SES identity for sending emails (can be a domain or email).

Follow the on-screen instructions to complete the deployment. For subsequent deployments, you can simply run `sam deploy`.

---

## 🤝 How to Contribute

Contributions are welcome! If you want to improve Posterit-E, please follow these steps:

1. **Fork** this repository.
2. Create a new branch for your feature:
   ```bash
   git checkout -b feature/new-feature
   ```
3. Make your changes and commit atomically.
4. **Push** to your branch:
   ```bash
   git push origin feature/new-feature
   ```
5. Open a **Pull Request** to the `main` branch of the original repository.

---

## 🤖 Context for AI Agents

This is a structured summary for AI agents and LLMs to quickly understand the project.

- **Main Objective:** Implement the backend of a digital legacy system (Posterit-E) using a serverless architecture on AWS.
- **Architectural Pillar:** The system is Zero-Knowledge. The server code MUST NEVER have access to plaintext passwords or user secrets. Cryptography is handled 100% on the client.
- **Non-Negotiable Security Rule:** Lambda functions should only receive and store data already encrypted from the client. Their responsibility is to manage metadata, state flows, and orchestrate the release process, but never to decrypt information.
- **Tech Stack:** Python, AWS Lambda, API Gateway, DynamoDB, S3.
- **IaC Framework:** AWS SAM. The `template.yaml` file is the single source of truth for AWS infrastructure.
- **Common Task:** A typical task would be to add or modify the logic of one of the Lambda functions in `functions/` and update its resource and permission definition in `template.yaml`.
