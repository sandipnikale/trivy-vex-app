# Developer Guide: Rancher VEX Scanner

This guide provides technical instructions for setting up the development environment, understanding the codebase, and contributing to the Rancher VEX Scanner project.

## 1. Prerequisites
To develop and test this application locally, you need:
*   **Python 3.11+**
*   **Docker Desktop** or **Colima** (for image builds)
*   **Trivy CLI**: [Installation Guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
*   **A Kubernetes Cluster**: K3s, Minikube, or Docker Desktop Kubernetes (required for scan execution).
*   **Gemini API Key**: (Optional) For testing AI correlation features.

---

## 2. Local Setup

### **A. Environment Configuration**
1.  **Clone the repository**:
    ```bash
    git clone https://github.com/rancher/trivy-vex-app.git
    cd trivy-vex-app
    ```
2.  **Create a Virtual Environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

### **B. Running the Application**
Run the FastAPI server using `uvicorn`:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```
*   The application will be available at `http://localhost:8080`.
*   Note: While the UI will work, **scans will fail** if the application cannot reach a Kubernetes API.

---

## 3. Project Structure
```text
.
├── app/
│   ├── main.py          # Core logic (FastAPI, K8s Client, AI Integration)
│   ├── static/          # CSS, JS, and image assets
│   └── templates/       # Jinja2 HTML templates (HTMX powered)
├── charts/              # Helm chart for Kubernetes deployment
├── Dockerfile           # Multi-stage build (Python + Trivy)
├── requirements.txt     # Python dependencies
└── document.md          # User & Demo Guide
```

---

## 4. Key Implementation Patterns

### **HTMX & Frontend Reactivity**
We avoid heavy frontend frameworks. Interactivity is handled via **HTMX**:
*   Most UI actions are `hx-post` or `hx-get` triggers.
*   Background process updates are handled via **Server-Sent Events (SSE)** in `app/main.py` (`/scan/batch/progress/{job_id}`).

### **Kubernetes Job Orchestration**
The application uses the `kubernetes` Python client to spawn ephemeral scan jobs.
*   **Location**: `run_scan` and `_run_batch_worker` functions in `app/main.py`.
*   **Logic**: Jobs are configured with a **ServiceAccount** that has permissions to create/delete Jobs and read Pod logs.

### **VEX Integration**
The tool clones/downloads the `rancher-vexhub` repository at runtime inside the Trivy container to ensure the absolute latest triage data is used.

---

## 5. Building & Testing

### **Docker Build**
```bash
docker build -t trivy-vex-app:latest .
```

### **Helm Lint & Test**
```bash
helm lint charts/trivy-vex-app
helm install --dry-run --debug demo charts/trivy-vex-app
```

---

## 6. Troubleshooting
*   **"K8s Config Not Found"**: The app tries `load_incluster_config()` first, then falls back to `~/.kube/config`. Ensure your current shell has an active Kube context.
*   **Trivy Scan Timeouts**: Large images can take 2-3 minutes. If scans time out, check the `Job` logs in Kubernetes for pull errors or resource constraints.
*   **Gemini 404 Errors**: Ensure your API key has access to the `gemini-2.0-flash` model.
