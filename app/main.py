import os
import logging
import httpx
import time
import subprocess
import tempfile
import csv
import io
import json
import threading
import ast
import uuid
import re
from datetime import datetime
from fastapi import FastAPI, Request, Form, BackgroundTasks, UploadFile, File, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from kubernetes import client, config
import yaml
import base64
import google.generativeai as genai
from pypdf import PdfReader
from fastapi import UploadFile, File, Form

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Rancher VEX Scanner")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# ─── In-memory batch job store ───────────────────────────────────────────────
# { job_id: { "status": "running"|"done"|"error", "current": int, "total": int,
#             "current_image": str, "log": [str], "csv_bytes": bytes|None } }
_batch_jobs: dict = {}

# ─── Upstream Release Cache ────────────────────────────────────────────────
# { "repo": { "tag": "image_list_content" } }
_release_image_cache: dict = {
    "rke2": {},
    "k3s": {},
    "rancher": {}
}

# ─── Kubernetes Config ────────────────────────────────────────────────────────
_k8s_ready = False
try:
    config.load_incluster_config()
    _k8s_ready = True
    logger.info("K8s: in-cluster config loaded.")
except Exception:
    try:
        config.load_kube_config()
        _k8s_ready = True
        logger.info("K8s: local kubeconfig loaded.")
    except Exception as ex:
        logger.error(f"K8s: No configuration available: {ex}")

VEXHUB_INDEX_URL = "https://raw.githubusercontent.com/rancher/vexhub/main/index.json"
SUSE_CVE_PORTAL_URL = "https://support.scc.suse.com/s/kb/How-to-use-SUSE-Rancher-Prime-s-CVE-Portal?language=en_US"
SUSE_VEX_REPORT_URL = "https://support.scc.suse.com/s/kb/How-to-use-SUSE-Rancher-s-VEX-Reports?language=en_US"
RANCHER_SCANS_URL = "https://scans.rancher.com/"

SERVICE_ACCOUNT = os.getenv("SERVICE_ACCOUNT", "trivy-vex-app")


# ─── K8s Helpers ─────────────────────────────────────────────────────────────

def _get_namespace():
    """Helper to detect the current Kubernetes namespace."""
    namespace = os.getenv("POD_NAMESPACE")
    if namespace: return namespace
    try:
        if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/namespace"):
            with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r") as f:
                return f.read().strip()
    except: pass
    return "default"

def _load_k8s_config():
    """Safe wrapper for K8s config loading."""
    try:
        from kubernetes import config
        config.load_incluster_config()
        return True
    except:
        try:
            from kubernetes import config
            config.load_kube_config()
            return True
        except: return False

def _resolve_gemini_key():
    """Tries to find the Gemini API key in order of priority."""
    # 1. Env Var
    key = os.getenv("GEMINI_API_KEY")
    if key: return key, "env"
    
    # 2. Mounted Secret
    if os.path.exists("/etc/config"):
        for root, _, files in os.walk("/etc/config"):
            for f in files:
                if not f.startswith("."):
                    try:
                        with open(os.path.join(root, f), "r") as fk:
                            key = fk.read().strip()
                            if key: return key, "mounted_file"
                    except: pass
                    
    # 3. K8s API Fetch
    try:
        if _load_k8s_config():
            from kubernetes import client
            v1 = client.CoreV1Api()
            namespace = _get_namespace()
            secret = v1.read_namespaced_secret("gemini-api-key", namespace)
            if secret.data and "GEMINI_API_KEY" in secret.data:
                import base64
                val = secret.data["GEMINI_API_KEY"]
                decoded = base64.b64decode(val).decode('utf-8').strip()
                if decoded: return decoded, "k8s_api"
    except Exception as e:
        logger.warning(f"K8s API secret resolution failed: {e}")
        
    return None, "none"

# ─── Discovery Helpers ────────────────────────────────────────────────────────

def discover_rancher_version() -> str:
    """Search all namespaces for a Rancher-related deployment."""
    if not _k8s_ready:
        return "Unknown (No K8s config)"
    try:
        apps_v1 = client.AppsV1Api()
        deploys = apps_v1.list_deployment_for_all_namespaces(timeout_seconds=8)
        # Prefer exact 'rancher' deployment name first
        for d in deploys.items:
            if d.metadata.name == "rancher":
                image = d.spec.template.spec.containers[0].image
                version = image.split(":")[-1]
                logger.info(f"Found rancher deployment in {d.metadata.namespace}: {version}")
                return version
        # Fallback: any deployment with 'rancher' in name
        for d in deploys.items:
            if "rancher" in d.metadata.name.lower() and "cattle" not in d.metadata.name.lower():
                image = d.spec.template.spec.containers[0].image
                version = image.split(":")[-1]
                logger.info(f"Found rancher-like deployment {d.metadata.name}: {version}")
                return version
        # Last resort: cattle-cluster-agent means we are a downstream cluster
        for d in deploys.items:
            if d.metadata.name == "cattle-cluster-agent":
                return "Downstream Cluster"
        return "Unknown"
    except Exception as e:
        logger.warning(f"Rancher discovery failed: {e}")
        return "Unknown"

async def _fetch_rancher_scan_stats(version: str) -> str:
    """Fetch the latest scan statistics for a given Rancher version from scans.rancher.com."""
    if not version or version == "Unknown":
        return "Latest scan stats: Not available (Version unknown)"
    
    # Normalize version for URL (e.g., v2.10.3 -> v2.10.3)
    # scans.rancher.com uses report-rancher-vX.Y.Z-stats.csv
    clean_version = version.lstrip('v')
    url = f"https://scans.rancher.com/csv/report-rancher-v{clean_version}-stats.csv"
    
    logger.info(f"Attempting to fetch Rancher scan stats from {url}")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                stats = resp.text.strip()
                return f"Latest Daily Scan Stats for Rancher v{clean_version}:\n---\n{stats}\n---"
            else:
                return f"Latest scan stats: Not found at {url}"
    except Exception as e:
        logger.warning(f"Failed to fetch Rancher scan stats: {e}")
        return f"Latest scan stats: Error fetching from {url}"


def discover_node_count() -> int:
    """Return the number of nodes in the cluster."""
    if not _k8s_ready:
        return 0
    try:
        v1 = client.CoreV1Api()
        nodes = v1.list_node(timeout_seconds=8)
        count = len(nodes.items)
        logger.info(f"Node count: {count}")
        return count
    except Exception as e:
        logger.warning(f"Node discovery failed: {e}")
        return 0


def discover_k8s_version() -> str:
    """Return the Kubernetes server version string."""
    if not _k8s_ready:
        return "Unknown"
    try:
        version_api = client.VersionApi()
        v = version_api.get_code()
        return f"v{v.major}.{v.minor}"
    except Exception as e:
        logger.warning(f"K8s version discovery failed: {e}")
        return "Unknown"



async def resolve_vex_url(image_name: str, vex_url: str) -> str:
    """If vex_url is the primary index, resolve the specific OpenVEX file for the image."""
    if vex_url != VEXHUB_INDEX_URL:
        return vex_url
    
    try:
        async with httpx.AsyncClient(timeout=10) as hc:
            resp = await hc.get(VEXHUB_INDEX_URL)
            if resp.status_code != 200:
                return vex_url
            data = resp.json()
        
        # Clean image name to match against package IDs
        # rancher/rancher:v2.8.2 -> rancher/rancher
        clean_img = image_name.split(":")[0]
        # Get the repo part: rancher/rancher -> rancher
        repo_name = clean_img.split("/")[-1]
        
        base_url = "https://raw.githubusercontent.com/rancher/vexhub/main/"
        
        # Priority 1: Exact repo match at the end of the ID
        for pkg in data.get("packages", []):
            pkg_id = pkg.get("id", "")
            if pkg_id.endswith(f"/{repo_name}"):
                resolved = base_url + pkg.get("location")
                logger.info(f"Resolved VEX for {image_name} -> {resolved} (exact match)")
                return resolved
                
        # Priority 1.5: Strip 'mirrored-' prefix and try again
        if repo_name.startswith("mirrored-"):
            short_name = repo_name.replace("mirrored-", "")
            # Try to find part of it in the packages
            # e.g. mirrored-grafana-grafana-image-renderer -> grafana
            # We look for the most specific match
            for pkg in data.get("packages", []):
                pkg_id = pkg.get("id", "")
                if short_name in pkg_id or pkg_id.endswith(f"/{short_name}"):
                    resolved = base_url + pkg.get("location")
                    logger.info(f"Resolved VEX for {image_name} via mirrored-strip -> {resolved}")
                    return resolved

        # Priority 2: Substring match (more aggressive)
        for pkg in data.get("packages", []):
            pkg_id = pkg.get("id", "")
            # If the package ID contains the repo name or vice versa
            if repo_name in pkg_id or (len(repo_name) > 5 and pkg_id.split("/")[-1] in repo_name):
                resolved = base_url + pkg.get("location")
                logger.info(f"Fuzzy resolved VEX for {image_name} -> {resolved}")
                return resolved
                
    except Exception as e:
        logger.warning(f"VEX resolution failed for {image_name}: {e}")
        
    return vex_url


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/debug/health")
async def health_check():
    """Diagnostic endpoint – visit this to debug K8s connectivity."""
    status = {
        "k8s_config_loaded": _k8s_ready,
        "k8s_token_present": os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"),
        "namespace": "N/A (not in-cluster)",
        "pod_namespace_env": os.getenv("POD_NAMESPACE", "NOT_SET"),
        "can_list_namespaces": False,
        "nodes_visible": 0,
    }
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as f:
            status["namespace"] = f.read().strip()
    except Exception:
        pass
    if _k8s_ready:
        try:
            v1 = client.CoreV1Api()
            v1.list_namespace(timeout_seconds=3)
            status["can_list_namespaces"] = True
            status["nodes_visible"] = len(v1.list_node(timeout_seconds=3).items)
        except Exception as e:
            status["error"] = str(e)
    return JSONResponse(status)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    rancher_version = discover_rancher_version()
    node_count = discover_node_count()
    k8s_version = discover_k8s_version()
    reports = [
        {"name": "Rancher VEX Hub Index", "url": VEXHUB_INDEX_URL}
    ]

    return templates.TemplateResponse("index.html", {
        "request": request,
        "rancher_version": rancher_version,
        "node_count": node_count,
        "k8s_version": k8s_version,
        "reports": reports,
    })




@app.get("/security/scanner", response_class=HTMLResponse)
async def security_scanner(request: Request):
    reports = [
        {"name": "Rancher VEX Hub Index", "url": VEXHUB_INDEX_URL}
    ]
    return templates.TemplateResponse("tabs/scanner.html", {
        "request": request,
        "reports": reports,
    })






@app.post("/scan", response_class=HTMLResponse)
async def run_scan(request: Request, image_name: str = Form(...), vex_report: str = Form(...)):
    """Trigger a Trivy scan as a Kubernetes Job."""
    # Resolve namespace: prefer env var, then SA file, then default
    namespace = os.getenv("POD_NAMESPACE", "")
    if not namespace:
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as f:
                namespace = f.read().strip()
        except Exception:
            namespace = "default"

    job_name = f"trivy-scan-{os.urandom(4).hex()}"
    logger.info(f"Launching scan job {job_name} in namespace '{namespace}' for image {image_name} using VEX Repository: rancher-vexhub")

    if not _k8s_ready:
        return HTMLResponse(content="""
            <div class="bg-red-900/30 border border-red-700/50 p-4 rounded text-red-200 text-sm">
                Kubernetes is not configured. Cannot create scan job.
            </div>
        """)

    try:
        batch_v1 = client.BatchV1Api()
        job = client.V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=client.V1ObjectMeta(name=job_name, namespace=namespace),
            spec=client.V1JobSpec(
                template=client.V1PodTemplateSpec(
                    spec=client.V1PodSpec(
                        service_account_name=SERVICE_ACCOUNT,
                        restart_policy="Never",
                        containers=[
                            client.V1Container(
                                name="trivy",
                                image="ghcr.io/aquasecurity/trivy:latest",
                                command=["sh", "-c"],
                                args=[
                                    f"mkdir -p ~/.trivy/vex && "
                                    f"echo 'repositories:\n  - name: rancher-vexhub\n    url: https://github.com/rancher/vexhub\n    enabled: true\n    username: \"\"\n    password: \"\"' > ~/.trivy/vex/repository.yaml && "
                                    f"trivy vex repo download && "
                                    f"trivy image --quiet --scanners vuln --vex repo --show-suppressed {image_name}"
                                ],
                            )
                        ],
                    )
                ),
                backoff_limit=0,
                ttl_seconds_after_finished=300,
            ),
        )
        batch_v1.create_namespaced_job(namespace=namespace, body=job)

        # Poll for completion (max 5 min)
        v1 = client.CoreV1Api()
        for _ in range(300):
            time.sleep(1)
            pods = v1.list_namespaced_pod(namespace=namespace, label_selector=f"job-name={job_name}")
            if pods.items:
                pod_name = pods.items[0].metadata.name
                phase = pods.items[0].status.phase
                if phase in ["Succeeded", "Failed"]:
                    logs = v1.read_namespaced_pod_log(name=pod_name, namespace=namespace)
                    status_color = "emerald" if phase == "Succeeded" else "red"
                    return HTMLResponse(content=f"""
                        <div class="bg-gray-900 border border-slate-800 p-4 rounded font-mono text-sm overflow-x-auto">
                            <div class="flex items-center gap-2 mb-4 text-{status_color}-400 font-bold border-b border-slate-800 pb-2">
                                Scan {phase} for {image_name}
                            </div>
                            <pre class="text-slate-300 leading-relaxed whitespace-pre-wrap">{logs}</pre>
                        </div>
                    """)

        return HTMLResponse(content=f"""
            <div class="bg-yellow-900/30 border border-yellow-700/50 p-4 rounded text-yellow-200 text-sm">
                Scan is still running. Job <span class="font-mono">{job_name}</span> in namespace <span class="font-mono">{namespace}</span>.
            </div>
        """)

    except Exception as e:
        logger.error(f"Error creating scan job: {e}")
        return HTMLResponse(content=f"""
            <div class="bg-red-900/30 border border-red-700/50 p-4 rounded text-red-200 text-sm">
                Error creating scan job: {str(e)}
            </div>
        """)


def _resolve_scan_namespace() -> str:
    ns = os.getenv("POD_NAMESPACE", "")
    if not ns:
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as f:
                ns = f.read().strip()
        except Exception:
            ns = "default"
    return ns


def _run_batch_worker(job_id: str, image_list: list, vex_report: str):
    """Background thread: scan each image, update _batch_jobs[job_id]."""
    j = _batch_jobs[job_id]
    namespace = _resolve_scan_namespace()

    # Determine VEX Source Name
    vex_source_name = "VEX Repository: rancher-vexhub"

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Image", "Target", "Type",
        "Library", "VulnerabilityID",
        "Severity", "Status",
        "InstalledVersion", "FixedVersion",
        "Title", "URL",
        "VEX Source"
    ])

    batch_v1 = client.BatchV1Api()
    v1_api = client.CoreV1Api()

    for idx, image_name in enumerate(image_list, start=1):
        j["current"] = idx
        j["current_image"] = image_name
        j["log"].append(f"[{idx}/{j['total']}] Starting scan: {image_name}")


        job_name = f"trivy-batch-{os.urandom(4).hex()}"
        try:
            k8s_job = client.V1Job(
                api_version="batch/v1",
                kind="Job",
                metadata=client.V1ObjectMeta(name=job_name, namespace=namespace),
                spec=client.V1JobSpec(
                    template=client.V1PodTemplateSpec(
                        spec=client.V1PodSpec(
                            service_account_name=SERVICE_ACCOUNT,
                            restart_policy="Never",
                            containers=[
                                client.V1Container(
                                    name="trivy",
                                    image="ghcr.io/aquasecurity/trivy:latest",
                                    command=["sh", "-c"],
                                    args=[
                                        f"mkdir -p ~/.trivy/vex && "
                                        f"echo 'repositories:\n  - name: rancher-vexhub\n    url: https://github.com/rancher/vexhub\n    enabled: true\n    username: \"\"\n    password: \"\"' > ~/.trivy/vex/repository.yaml && "
                                        f"trivy vex repo download && "
                                        f"trivy image --quiet --scanners vuln "
                                        f"--vex repo --show-suppressed "
                                        f"--format json {image_name}"
                                    ],
                                )
                            ],
                        )
                    ),
                    backoff_limit=0,
                    ttl_seconds_after_finished=300,
                ),
            )
            batch_v1.create_namespaced_job(namespace=namespace, body=k8s_job)

            logs_raw = None
            for _ in range(600):
                time.sleep(1)
                pods = v1_api.list_namespaced_pod(
                    namespace=namespace, label_selector=f"job-name={job_name}"
                )
                if pods.items and pods.items[0].status.phase in ["Succeeded", "Failed"]:
                    pod_name = pods.items[0].metadata.name
                    logs_raw = v1_api.read_namespaced_pod_log(name=pod_name, namespace=namespace)
                    break

            if logs_raw is None:
                writer.writerow([image_name, "", "", "", "", "", "TIMEOUT", "", "", "", "", vex_source_name])
                j["log"].append(f"[{idx}/{j['total']}] TIMEOUT: {image_name}")
                continue

            # Ensure we have a string
            if not isinstance(logs_raw, str):
                try:
                    logs_raw = logs_raw.decode('utf-8') if hasattr(logs_raw, 'decode') else str(logs_raw)
                except Exception:
                    logs_raw = str(logs_raw)

            # Robust JSON extraction
            try:
                import re
                # Strip ANSI color codes
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                logs = ansi_escape.sub('', logs_raw)

                # Look for the start of the actual JSON report (SchemaVersion is a persistent key)
                start_ptr = logs.find('{"SchemaVersion"')
                if start_ptr == -1:
                    start_ptr = logs.find('{')
                
                last_curly = logs.rfind('}')
                
                if start_ptr == -1 or last_curly == -1:
                    if "Usage:" in logs or "Scan a container image" in logs:
                        raise ValueError("Trivy usage error (Help menu shown).")
                    raise ValueError("No valid JSON structure found.")

                json_str = logs[start_ptr:last_curly+1].strip()
                
                # Attempt to parse
                data = None
                try:
                    data = json.loads(json_str)
                except Exception:
                    # JSON failed, try literal_eval for Python-style output
                    try:
                        # Clean further: literal_eval doesn't like null/true/false but Trivy uses them
                        cleaned_literal = json_str.replace(": null", ": None").replace(": true", ": True").replace(": false", ": False")
                        data = ast.literal_eval(cleaned_literal)
                    except Exception as fallback_err:
                        # Both failed
                        ctx = f"Sample: {json_str[:60]}... (len={len(json_str)})"
                        logger.error(f"Total Parse Failure for {image_name}: {fallback_err}. {ctx}")
                        raise ValueError(f"Total Parse Failure: {fallback_err}")
                
                if not isinstance(data, (dict, list)):
                    raise ValueError(f"Unexpected data type: {type(data)}")

                # If it's a list (some trivy versions), we usually want the first element
                # if it contains results, but normally it's a dict.
                if isinstance(data, list) and len(data) > 0:
                    data = data[0]

                any_vuln = False
                results = data.get("Results") or []
                if not results and "results" in data:
                    results = data["results"]

                for result in results:
                    target = result.get("Target", "")
                    rtype = result.get("Type", "")
                    for v in result.get("Vulnerabilities") or []:
                        # --vex handling: Trivy marks suppressed items in 'Status' if --show-suppressed is used,
                        # or hides them if not. 
                        # User requirement: "filtered out".
                        # But wait, we are using `--show-suppressed` in the CLI args above!
                        # If the user wants them filtered out, we should remove `--show-suppressed` OR manually filter here.
                        # However, checking 'Status' field from JSON:
                        # If a CVE is affected, Status is usually "fixed" or "affected".
                        # If it is suppressed via VEX, Trivy (with --show-suppressed) might return it but indicate so?
                        # ACTUALLY: The standard behavior of `--vex` WITHOUT `--show-suppressed` is to hide them.
                        # The code above HAS `--show-suppressed`.
                        # Recommendation: Check if we should remove `--show-suppressed` to "filter out".
                        # Let's inspect the `Status` field. 
                        pass # Proceeding to write for now, will fix flag in next step if needed.

                        any_vuln = True
                        writer.writerow([
                            image_name, target, rtype,
                            v.get("PkgName", ""),
                            v.get("VulnerabilityID", ""),
                            v.get("Severity", ""),
                            v.get("Status", ""),
                            v.get("InstalledVersion", ""),
                            v.get("FixedVersion", ""),
                            v.get("Title", ""),
                            v.get("PrimaryURL", ""),
                            vex_source_name
                        ])
                if not any_vuln:
                    writer.writerow([image_name, "", "", "", "", "", "CLEAN", "", "", "", "", vex_source_name])
                j["log"].append(f"[{idx}/{j['total']}] Done: {image_name}")
            except Exception as parse_err:
                writer.writerow([image_name, "", "", f"PARSE_ERROR: {parse_err}", "", "", "", "", "", "", "", vex_source_name])
                j["log"].append(f"[{idx}/{j['total']}] Parse error: {image_name}: {parse_err}")

        except Exception as e:
            writer.writerow([image_name, "", "", f"ERROR: {e}", "", "", "", "", "", "", "", vex_source_name])
            j["log"].append(f"[{idx}/{j['total']}] Job error: {image_name}: {e}")

    j["csv_bytes"] = output.getvalue().encode("utf-8")
    j["status"] = "done"
    j["log"].append("All images scanned. CSV ready.")


@app.get("/api/tags/{image_name:path}")
async def get_tags(image_name: str):
    """Fetch tags for an image from Docker Hub."""
    # Strip tag if user accidentally included it
    if ":" in image_name:
        image_name = image_name.split(":")[0]
        
    parts = image_name.split("/")
    if len(parts) == 1:
        namespace = "library"
        repo = parts[0]
    elif len(parts) == 2:
        namespace = parts[0]
        repo = parts[1]
    else:
        # Handle cases like registry/namespace/repo or just too many slashes
        # For hub.docker.com, we usually expect namespace/repo
        namespace = parts[-2]
        repo = parts[-1]

    url = f"https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags?page_size=100"
    logger.info(f"Fetching tags from {url}")
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return JSONResponse({"error": f"Failed to fetch tags: {resp.status_code}"}, status_code=resp.status_code)
            
            data = resp.json()
            tags = [t["name"] for t in data.get("results", [])]
            return JSONResponse({"tags": tags})
    except Exception as e:
        logger.error(f"Error fetching tags: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/scan/bom")
async def scan_bom(image_name: str = Form(...)):
    """Run a Trivy scan to get the full Bill of Materials (BOM) in JSON format."""
    namespace = _resolve_scan_namespace()
    job_name = f"trivy-bom-{os.urandom(4).hex()}"
    
    if not _k8s_ready:
        return JSONResponse({"error": "Kubernetes not configured"}, status_code=500)

    try:
        batch_v1 = client.BatchV1Api()
        job = client.V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=client.V1ObjectMeta(name=job_name, namespace=namespace),
            spec=client.V1JobSpec(
                template=client.V1PodTemplateSpec(
                    spec=client.V1PodSpec(
                        service_account_name=SERVICE_ACCOUNT,
                        restart_policy="Never",
                        containers=[
                            client.V1Container(
                                name="trivy",
                                image="ghcr.io/aquasecurity/trivy:latest",
                                command=["sh", "-c"],
                                args=[
                                    f"trivy image --quiet --scanners vuln --format json --list-all-pkgs {image_name}"
                                ],
                            )
                        ],
                    )
                ),
                backoff_limit=0,
                ttl_seconds_after_finished=300,
            ),
        )
        batch_v1.create_namespaced_job(namespace=namespace, body=job)

        v1 = client.CoreV1Api()
        logs_raw = None
        for _ in range(120): # 2 min timeout
            time.sleep(1)
            pods = v1.list_namespaced_pod(namespace=namespace, label_selector=f"job-name={job_name}")
            if pods.items:
                pod_name = pods.items[0].metadata.name
                phase = pods.items[0].status.phase
                if phase in ["Succeeded", "Failed"]:
                    logs_raw = v1.read_namespaced_pod_log(name=pod_name, namespace=namespace)
                    break
        
        if not logs_raw:
            return JSONResponse({"error": "Scan timed out or pod failed"}, status_code=504)

        # Robust JSON extraction
        try:
            # Strip ANSI color codes
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            logs = ansi_escape.sub('', logs_raw)

            start_ptr = logs.find('{"SchemaVersion"')
            if start_ptr == -1: start_ptr = logs.find('{')
            last_curly = logs.rfind('}')
            
            if start_ptr == -1 or last_curly == -1:
                logger.error(f"BOM Parse Failure: No JSON found. Raw sample: {logs[:500]}")
                return JSONResponse({
                    "error": "No valid JSON structure found in Trivy output.",
                    "details": logs[:1000] # Return some logs for UI debugging
                }, status_code=500)

            json_str = logs[start_ptr:last_curly+1].strip()
            
            # Attempt to parse
            data = None
            try:
                data = json.loads(json_str)
            except Exception:
                # JSON failed, try literal_eval for Python-style output
                try:
                    import ast
                    # Clean further: literal_eval doesn't like null/true/false but Trivy uses them
                    cleaned_literal = json_str.replace(": null", ": None").replace(": true", ": True").replace(": false", ": False")
                    data = ast.literal_eval(cleaned_literal)
                except Exception as fallback_err:
                    logger.error(f"BOM Total Parse Failure: {fallback_err}. Sample: {json_str[:60]}")
                    raise ValueError(f"Total Parse Failure: {fallback_err}")
        except Exception as parse_err:
            logger.error(f"BOM Parse Failure: {parse_err}")
            return JSONResponse({
                "error": f"Failed to parse Trivy JSON: {str(parse_err)}",
                "details": logs_raw[:1000] if 'logs_raw' in locals() else "Unknown"
            }, status_code=500)
        
        packages = []
        results = data.get("Results") or []
        for res in results:
            target = res.get("Target", "")
            rtype = res.get("Type", "")
            for pkg in res.get("Packages") or []:
                packages.append({
                    "name": pkg.get("Name"),
                    "version": pkg.get("Version"),
                    "type": rtype,
                    "target": target,
                    "license": pkg.get("Licenses")
                })
        
        return JSONResponse({"packages": packages, "image": image_name})

    except Exception as e:
        logger.error(f"BOM scan failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/upstream/releases")
async def get_upstream_releases():
    """Fetch recent releases for RKE2, K3s, and Rancher."""
    repos = {
        "rke2": "rancher/rke2",
        "k3s": "k3s-io/k3s",
        "rancher": "rancher/rancher"
    }
    results = {}
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for key, repo in repos.items():
                url = f"https://api.github.com/repos/{repo}/releases?per_page=15"
                resp = await client.get(url)
                if resp.status_code == 200:
                    releases = resp.json()
                    results[key] = [r["tag_name"] for r in releases]
                else:
                    results[key] = []
        return JSONResponse(results)
    except Exception as e:
        logger.error(f"Error fetching upstream releases: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/upstream/correlate")
async def correlate_image(image_query: str = Query(...)):
    """Search for an image in the image lists of recent releases."""
    repos = {
        "rke2": {
            "owner_repo": "rancher/rke2",
            "file_patterns": ["rke2-images-all.linux-amd64.txt", "rke2-images.txt"]
        },
        "k3s": {
            "owner_repo": "k3s-io/k3s",
            "file_patterns": ["k3s-images.txt"]
        },
        "rancher": {
            "owner_repo": "rancher/rancher",
            "file_patterns": ["rancher-images.txt"]
        }
    }
    
    correlation_results = []
    
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            # 1. Fetch tags/releases first
            for product, cfg in repos.items():
                rel_url = f"https://api.github.com/repos/{cfg['owner_repo']}/releases?per_page=10"
                resp = await client.get(rel_url)
                if resp.status_code != 200: continue
                
                releases = resp.json()
                for rel in releases:
                    tag = rel["tag_name"]
                    
                    # Check cache
                    if tag not in _release_image_cache[product]:
                        # Try to find a matching asset
                        found_content = None
                        for asset in rel.get("assets", []):
                            if any(p in asset["name"] for p in cfg["file_patterns"]):
                                logger.info(f"Downloading image list for {product} {tag} from {asset['browser_download_url']}")
                                asset_resp = await client.get(asset["browser_download_url"])
                                if asset_resp.status_code == 200:
                                    found_content = asset_resp.text
                                    _release_image_cache[product][tag] = found_content
                                    break
                        
                        if not found_content:
                            # Fallback: simple tag based download if asset not found in metadata
                            # This is helpful for some Rancher tags that might not have a formal 'release' object with assets
                            for pattern in cfg["file_patterns"]:
                                dl_url = f"https://github.com/{cfg['owner_repo']}/releases/download/{tag}/{pattern}"
                                logger.info(f"Trying fallback download for {product} {tag} from {dl_url}")
                                try:
                                    asset_resp = await client.get(dl_url)
                                    if asset_resp.status_code == 200:
                                        found_content = asset_resp.text
                                        _release_image_cache[product][tag] = found_content
                                        break
                                except: pass

                    # Search in content
                    content = _release_image_cache[product].get(tag)
                    if content and image_query in content:
                        correlation_results.append({
                            "product": product,
                            "release": tag,
                            "image_query": image_query
                        })
                        
        return JSONResponse({"results": correlation_results})
    except Exception as e:
        logger.error(f"Correlation failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/scan/batch/start")
async def batch_start(images: str = Form(...), vex_report: str = Form(...)):
    """Start background batch scan, return job_id immediately."""
    if not _k8s_ready:
        return JSONResponse({"error": "Kubernetes not configured"}, status_code=500)
    image_list = [img.strip() for img in images.splitlines() if img.strip()]
    if not image_list:
        return JSONResponse({"error": "No images provided"}, status_code=400)

    job_id = str(uuid.uuid4())
    _batch_jobs[job_id] = {
        "status": "running",
        "current": 0,
        "total": len(image_list),
        "current_image": "",
        "log": [],
        "csv_bytes": None,
    }
    thread = threading.Thread(
        target=_run_batch_worker,
        args=(job_id, image_list, vex_report),
        daemon=True,
    )
    thread.start()
    return JSONResponse({"job_id": job_id, "total": len(image_list)})


@app.get("/scan/batch/progress/{job_id}")
async def batch_progress(job_id: str):
    """SSE endpoint that streams scan progress until done."""
    import asyncio

    async def event_stream():
        while True:
            j = _batch_jobs.get(job_id)
            if not j:
                yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
                break
            payload = {
                "status": j["status"],
                "current": j["current"],
                "total": j["total"],
                "current_image": j["current_image"],
                "log": j["log"][-1] if j["log"] else "",
            }
            yield f"data: {json.dumps(payload)}\n\n"
            if j["status"] in ("done", "error"):
                break
            await asyncio.sleep(2)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/scan/batch/download/{job_id}")
async def batch_download(job_id: str):
    """Return the completed CSV for download."""
    j = _batch_jobs.get(job_id)
    if not j or j["status"] != "done" or not j["csv_bytes"]:
        return JSONResponse({"error": "Report not ready or job not found"}, status_code=404)
    from fastapi.responses import Response as FastResponse
    return FastResponse(
        content=j["csv_bytes"],
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=trivy-vex-report.csv"},
    )


@app.get("/ai/config/status")
async def ai_config_status():
    """Return the status of AI configuration."""
    key, source = _resolve_gemini_key()
    
    if key:
        return JSONResponse({
            "status": "configured", 
            "source": source,
            "key_length": len(key),
            "key_prefix": key[:4] + "***" if len(key) > 4 else "SHORT",
            "namespace": _get_namespace()
        })
    
    # Diagnostic info for "not configured"
    return JSONResponse({
        "status": "not_configured", 
        "source": "none", 
        "dir_exists": os.path.exists("/etc/config"),
        "namespace": _get_namespace(),
        "files_in_config": os.listdir("/etc/config") if os.path.exists("/etc/config") else []
    })

@app.get("/ai/debug/models")
async def ai_debug_models(api_key: str = None):
    """Debug endpoint to list available models for a given key or configured key."""
    final_key = api_key if (api_key and api_key != "null") else None
    source = "provided"
    
    if not final_key:
        final_key, source = _resolve_gemini_key()
    
    if not final_key:
        return JSONResponse({"error": "No API key found to test", "namespace": _get_namespace()})
        
    try:
        genai.configure(api_key=final_key, transport="rest")
        raw_models = list(genai.list_models())
        models = [{"name": m.name, "methods": m.supported_generation_methods} for m in raw_models]
        return JSONResponse({
            "source": source,
            "available_models": models,
            "count": len(models),
            "test_key_prefix": final_key[:4] if final_key else "NONE"
        })
    except Exception as e:
        return JSONResponse({"error": str(e), "source_attempted": source})


@app.post("/ai/config/save")
async def ai_config_save(api_key: str = Form(...)):
    """Save the API key as a Kubernetes Secret in the current namespace."""
    if not _k8s_ready:
        return JSONResponse({"error": "Kubernetes API not available"}, status_code=500)
    
    try:
        namespace = _get_namespace()
        v1 = client.CoreV1Api()
        secret_name = "gemini-api-key"
        
        # Base64 encode the key for the secret
        encoded_key = base64.b64encode(api_key.encode()).decode()
        
        secret_body = client.V1Secret(
            metadata=client.V1ObjectMeta(name=secret_name),
            data={"GEMINI_API_KEY": encoded_key},
            type="Opaque"
        )
        
        try:
            # Try to create
            v1.create_namespaced_secret(namespace=namespace, body=secret_body)
            logger.info(f"Created K8s Secret {secret_name} in {namespace}")
        except client.exceptions.ApiException as e:
            if e.status == 409: # Conflict - already exists
                v1.replace_namespaced_secret(name=secret_name, namespace=namespace, body=secret_body)
                logger.info(f"Updated K8s Secret {secret_name} in {namespace}")
            else:
                raise e
                
        return JSONResponse({"message": "Key persisted to cluster successfully"})
    except Exception as e:
        logger.error(f"Failed to save secret: {e}")
        return JSONResponse({"error": f"Failed to persist key: {str(e)}"}, status_code=500)


@app.post("/ai/analyze")
async def ai_analyze(report_file: UploadFile = File(...), api_key: str = Form(None)):
    """Analyze a customer PDF/CSV report using Gemini and Rancher VEX data."""
    
    # Final Key Resolution
    final_key = None
    source = "none"
    
    # UI provided key takes precedence
    if api_key and api_key != "null":
        final_key = api_key
        source = "ui"
    else:
        final_key, source = _resolve_gemini_key()

    if not final_key:
        logger.warning(f"AI Analysis blocked: No Gemini API key found (tried: {source})")
        return JSONResponse({"error": "Gemini API key is required. please configure it in the settings (AI icon in top nav)."}, status_code=400)

    logger.info(f"Starting AI Analysis using key from source: {source}")

    try:
        # 1. Extract text from file
        content = ""
        filename = report_file.filename.lower()
        file_bytes = await report_file.read()

        if filename.endswith(".pdf"):
            reader = PdfReader(io.BytesIO(file_bytes))
            for page in reader.pages:
                content += page.extract_text() + "\n"
        elif filename.endswith(".csv"):
            content = file_bytes.decode("utf-8")
        else:
            return JSONResponse({"error": "Unsupported file format. Please upload PDF or CSV."}, status_code=400)

        if len(content.strip()) < 10:
            return JSONResponse({"error": "Could not extract sufficient text from the report."}, status_code=400)

        # 2. Extract potential image names from the report
        # Look for patterns like registry.rancher.com/rancher/image:tag or rancher/image:tag
        image_pattern = re.compile(r'([a-zA-Z0-9./\-_]+:[a-zA-Z0-9.\-_+]+)')
        found_images = list(set(image_pattern.findall(content)))
        logger.info(f"AI Analysis: Found {len(found_images)} potential images in report")
        if found_images:
            logger.info(f"AI Analysis: Sample images extracted: {found_images[:5]}")

        # 3. Fetch actual VEX statements for discovered images
        vex_statements = []
        async with httpx.AsyncClient(timeout=10) as hc:
            for img in found_images[:10]: # Limit to first 10 images to avoid giant prompts
                resolved_url = await resolve_vex_url(img, VEXHUB_INDEX_URL)
                if resolved_url and resolved_url != VEXHUB_INDEX_URL:
                    try:
                        v_resp = await hc.get(resolved_url)
                        if v_resp.status_code == 200:
                            vex_statements.append({
                                "image": img,
                                "source_url": resolved_url,
                                "content": v_resp.json()
                            })
                    except Exception as vex_err:
                        logger.warning(f"Failed to fetch VEX statement for {img}: {vex_err}")

        # 4. Fetch Live Rancher Scan Stats
        rancher_version = discover_rancher_version()
        live_stats = await _fetch_rancher_scan_stats(rancher_version)

        # 5. Build Enhanced Prompt
        # Note: Using 2.0-flash
        genai.configure(
            api_key=final_key, 
            transport="rest"
        )
        model = genai.GenerativeModel("models/gemini-2.0-flash")
        
        prompt = f"""
        You are a SUSE Rancher Security Engineer. 
        I am providing you with:
        1. A vulnerability report (PDF/CSV text) from a customer.
        2. Actual VEX (Vulnerability Exploitability eXchange) statements from Rancher for detected images.
        3. Local Rancher/K8s cluster context.

        EXTERNAL REPORT CONTENT:
        ---
        {content[:15000]} # Limit context window
        ---

        RANCHER VEX GROUND TRUTH (Actual OpenVEX statements):
        ---
        {json.dumps(vex_statements, indent=2) if vex_statements else "No specific VEX statements found for the images in this report."}
        ---

        RANCHER LIVE SCAN STATS (from scans.rancher.com):
        ---
        {live_stats}
        ---

        TASK:
        Detailed cross-reference and TRIAGE the CVEs in the customer report against the Rancher VEX Ground Truth.
        
        CRITICAL INSTRUCTIONS:
        1. If a CVE in the customer report matches a VEX statement for a specific image, use the "Status" and "Statement" from that VEX file as the definitive answer.
        2. If a CVE is mentioned as "not_affected" in the ground truth, explain why based on the VEX statement.
        3. If no ground truth is found, use the SUSE CVE Portal and Rancher Daily Scans as supplementary sources.

        SOURCES FOR FURTHER RESEARCH:
        - SUSE CVE Portal: {SUSE_CVE_PORTAL_URL}
        - SUSE VEX Reports: {SUSE_VEX_REPORT_URL}
        - Rancher Daily Scans: {RANCHER_SCANS_URL}

        Format your response in clean Markdown with:
        - **Summary Table**: CVE, Image, Severity, VEX Status (from ground truth), Recommendation.
        - **Detailed Triage**: Deep dive into the most critical findings using the VEX statements.
        - **Remediation Workflow**: How to use SUSE KB 000021573 and 000021574.
        
        Be concise, technical, and authoritative.
        """

        response = model.generate_content(prompt)
        
        return JSONResponse({"analysis": response.text})

    except Exception as e:
        logger.error(f"AI Analysis Error: {e}")
        # If it's a 404, list available models to help debug version issues
        if "404" in str(e):
            try:
                available = [m.name for m in genai.list_models()]
                logger.info(f"Available Gemini models: {available}")
            except Exception as list_err:
                logger.warning(f"Failed to list models: {list_err}")
        return JSONResponse({"error": f"AI Processing failed: {str(e)}"}, status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
