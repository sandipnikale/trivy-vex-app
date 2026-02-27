# Trivy VEX App Helm Chart

This chart deploys the **Rancher VEX Scanner**, a web UI for scanning container images with Trivy and cross-referencing findings with Rancher VEX data.

## Features
- **FastAPI Backend**: Orchestrates Trivy scans as Kubernetes Jobs.
- **HTMX & Tailwind UI**: Responsive and dynamic web interface.
- **AI Triage**: Optional Gemini AI integration for CVE analysis.
- **Ingress Support**: Easy access via standard Ingress controllers.
- **Health Checks**: Standard liveness and readiness probes.

## Prerequisites
- Kubernetes 1.19+
- Helm 3.0+
- RBAC enabled (the app needs permissions to create Jobs and read cluster info)

## Installation

```bash
helm repo add trivy-vex-app https://<your-github-user>.github.io/<your-repo>/
helm install my-scanner trivy-vex-app/trivy-vex-app
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | App image repository | `trivy-vex-app` |
| `image.tag` | App image tag | `latest` |
| `ai.geminiApiKey` | Gemini API Key for AI Analysis | `""` |
| `ingress.enabled` | Enable Ingress | `false` |
| `service.port` | Service port | `80` |
| `rbac.create` | Create RBAC resources | `true` |

> [!IMPORTANT]
> To use the AI Triage feature, you must provide a `geminiApiKey` or have a secret named `gemini-api-key` in the namespace.
