# Rancher VEX Scanner: Project Overview & Demo Guide

## 1. Project Overview & Engineering Goals
The **Rancher VEX Scanner** is an **ephemeral security orchestration engine**. It bridges the gap between raw vulnerability telemetry (Trivy) and official security **"Ground Truth"** (VEX/VDB).

### **Core Problem: Triage Velocity**
*   **Low Signal-to-Noise Ratio**: Standard scanners generate exhaustive CVE lists. VEX-informed scanning identifies which findings are actually exploitable in the specific Rancher context.
*   **Manual Correlation Overhead**: Engineering teams manually map CVEs to SUSE/Rancher Prime advisories. This tool automates that mapping via cluster-aware discovery and AI.
*   **Data Siloing**: Integrates fragmented data sources (CVE Database, Rancher Scans portal, VEX Hub) into a unified **Analysis Engine**.

---

## 2. Key Features (The "Wow" Factor)
### **A. VEX-Driven Noise Suppression**
Applies **Vulnerability Exploitability eXchange (VEX)** data at runtime to triage results automatically.
*   Provides automated suppression for CVEs that have been verified by Engineering as "Not Affected" or "Fixed."
*   Exposes the **Engineering Logic** directly (e.g., *"library present but unimported"*), providing immediate audit-ready justification.

### **B. Environment-Specific Awareness (Auto-Discovery)**
The engine is **Stateless but Cluster-Aware**.
*   It auto-discovers Rancher/K8s versions to ensure the analysis is tailored to the specific **Upstream/Downstream** versions you are actually running.

### **C. AI-Powered Triage (RAG-lite Pattern)**
*   **The Scenario**: A customer provides a bulk scan report (PDF/CSV) with hundreds of un-triaged findings.
*   **The Intelligence**: The tool uses an **AI Correlation Engine (Gemini 2.0)** to cross-reference customer findings with internal Rancher VEX data, providing an instant human-readable triage report.

---

## 3. Technical Architecture
*   **Backend**: FastAPI (Python) – Lightweight and high-performance.
*   **Frontend**: HTMX & Tailwind CSS – Modern, reactive UI without the bloat of a heavy SPA.
*   **Executors**: Kubernetes Jobs – Scans run as isolated, ephemeral pods. This scales horizontally without impacting the main web server.
*   **Bridge**: Integrated with `rancher/vexhub` and `scans.rancher.com`.

---

## 4. How it's different from existing tools
| Feature | Standard Scanners (Raw Trivy/Grype) | Rancher VEX Scanner |
| :--- | :--- | :--- |
| **Filtered Results** | No (Reports everything) | **Yes** (Hides noise using VEX) |
| **Context** | None | **Cluster-Aware** (Knows your Rancher version) |
| **Report Triage** | Manual manual analysis | **AI-Automated** (Gemini correlation) |
| **Upstream Info** | Hard to find | **Bundled Release Finder** (Finds fix versions) |

---

## 5. UI Sections: Behind the Scenes
How each component handles data and orchestration:

### **Tab 1: Single Image Scan**
*   **Behind the scenes**: 
    1.  Orchestrates an **ephemeral K8s Job** using the `aquasec/trivy` container.
    2.  Injects a VEX repository configuration at runtime to filter against `rancher/vexhub`.
    3.  Automates local resource cleanup via **Job TTL** after results are streamed to the backend.

### **Tab 2: Batch Scan**
*   **Behind the scenes**:
    1.  Processes image lists via an **Asynchronous Worker Lifecycle**.
    2.  State is managed via unique **Job IDs**; the frontend receives updates via **Server-Sent Events (SSE)** for highly reactive progress tracking.
    3.  Aggregates data into a comprehensive **VEX-enriched CSV** audit log.

### **Tab 3: Component Explorer**
*   **Behind the scenes**:
    1.  Uses **Docker Hub API Integration** for tag discovery.
    2.  Runs a **SBOM-only scan mode** to quickly index package versions without full vulnerability database lookups.

### **Tab 4: Release Finder**
*   **Behind the scenes**:
    1.  Indexes **Upstream Manifests** from GitHub Releases (RKE2, K3s, Rancher).
    2.  Provides near-instant correlation across thousands of images using a **server-side memory cache**.

### **Tab 5: AI Analysis (The Intelligence Layer)**
*   **Behind the scenes**:
    1.  **Extracts & Tokenizes**: Parses customer PDF/CSV telemetry.
    2.  **Context Augmentation**: Merges findings with **Live Cluster Context** and **Global VEX Ground Truth**.
    3.  **Triage Recommendation**: AI classifies findings as *Suppressed (VEX)*, *Affected (Live)*, or *Safe (False Positive)* based on the merged context.

---

## 6. Demo Flow Ideas
1.  **Tab 1: Single Scan**: Run a scan on `rancher/rancher:v2.8.2` and show the "VEX" status vs normal "Fixed" status.
2.  **Tab 4: Release Finder**: Search for a package (e.g., `coredns`) and show how it locates which RKE2/K3s releases bundle it.
3.  **Tab 5: AI Analysis**: (The highlight) Upload a sample CVE list and show Gemini correlating it with "Ground Truth" VEX data to provide instant answers.
