# Trivy VEX App Helm Chart

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Helm: v3](https://img.shields.io/badge/Helm-v3-blue.svg)

This chart deploys the **Rancher VEX Scanner**, a  web application designed to orchestrate container image scans using Trivy and cross-reference findings with Rancher-specific VEX (Vulnerability Exploitability eXchange) reports.

## 🚀 Features

- **Automated Scanning**: Triggers Trivy scans as ephemeral Kubernetes Jobs for maximum isolation.
- **VEX Correlation**: Automatically maps vulnerabilities to known Rancher VEX statements to reduce noise.
- **AI-Powered Triage**: Optional integration with Google Gemini AI for intelligent CVE analysis and remediation advice.
- **Dynamic UI**: Responsive interface built with FastAPI, HTMX, and Tailwind CSS.
- **Observability**: Built-in health checks and liveness/readiness probes.

## 📋 Prerequisites

- **Kubernetes**: 1.19+
- **Helm**: 3.0+
- **RBAC**: Enabled on the cluster (the app requires permissions to manage Jobs and view cluster metadata).
- **Gemini API Key** (Optional): Required for AI Triage features.

## 🛠️ Installation

### 1. Add the Repository

```bash
helm repo add trivy-vex-app https://sandipnikale.github.io/trivy-vex-app/
helm repo update
```

### 2. Install the Chart

#### Default Installation
```bash
helm install my-scanner trivy-vex-app/trivy-vex-app
```

#### Installation with AI Analysis Enabled
```bash
helm install my-scanner trivy-vex-app/trivy-vex-app \
  --set ai.geminiApiKey="YOUR_GEMINI_API_KEY"
```

## ⚙️ Configuration

The following table lists the configurable parameters of the Trivy VEX App chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Docker image repository | `ghcr.io/sandipnikale/trivy-vex-app` |
| `image.tag` | Docker image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `Always` |
| `service.type` | Kubernetes Service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `ai.geminiApiKey` | Google Gemini API Key | `""` |
| `ingress.enabled` | Enable Ingress controller | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.hosts[0].host` | Ingress hostname | `chart-example.local` |
| `rbac.create` | Create required ClusterRole and RoleBindings | `true` |
| `resources.limits.cpu` | CPU limit | `200m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `probes.liveness.periodSeconds` | Liveness probe frequency | `10` |

## 🛡️ RBAC Permissions

The application requires specific permissions to function correctly:
- **Jobs**: `create`, `get`, `list`, `watch`, `delete` (to run Trivy scans).
- **Pods/Logs**: `get`, `list` (to retrieve scan results).
- **Nodes/Namespaces**: `get`, `list` (for cluster dashboard info).
- **Secrets**: `create`, `get` (if managing API keys via the UI).

By default, the chart creates the necessary ClusterRole and RoleBindings when `rbac.create` is `true`.

## ❓ Troubleshooting

### AI Feature Not Working
Verify that your Gemini API key is correct. You can also provide the key post-installation by creating a secret named `gemini-api-key` in the same namespace with the key `GEMINI_API_KEY`.

### Scans Stuck in "Pending"
Ensure your cluster has sufficient resources to schedule new Pods. The Trivy scans run as Jobs and require enough CPU/Memory to execute the `aquasec/trivy` image.


