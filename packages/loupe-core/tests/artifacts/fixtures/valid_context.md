---
schema_version: 1
last_human_edit: 2026-05-01
maintained_by: security-team@example.com
---

# Product Context

## Product description
Payment-processing API.

## Critical assets
- PAN
- CVV
- API keys

## Users and roles
- internal-service: callers from our own VPC
- ops-engineer: SREs with read-only log access

## Deployment
Containerized FastAPI on ECS Fargate.

## Threat actors of concern
- Compromised internal service
- Malicious insider

## Out of scope
- Customer-facing UI
