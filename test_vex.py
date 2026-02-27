import re
import json
import httpx
import asyncio

VEXHUB_INDEX_URL = "https://raw.githubusercontent.com/rancher/vexhub/main/index.json"

async def resolve_vex_url(image_name: str):
    clean_img = image_name.split(":")[0]
    repo_name = clean_img.split("/")[-1]
    
    print(f"DEBUG: repo_name extracted: {repo_name}")
    
    async with httpx.AsyncClient(timeout=10) as hc:
        resp = await hc.get(VEXHUB_INDEX_URL)
        data = resp.json()

    base_url = "https://raw.githubusercontent.com/rancher/vexhub/main/"
    
    # Priority 1: Exact repo match at the end of the ID
    for pkg in data.get("packages", []):
        pkg_id = pkg.get("id", "")
        if pkg_id.endswith(f"/{repo_name}"):
            return base_url + pkg.get("location"), "Exact Match"
            
    # Priority 1.5: Strip 'mirrored-' prefix and try again
    if repo_name.startswith("mirrored-"):
        short_name = repo_name.replace("mirrored-", "")
        print(f"DEBUG: mirrored-strip result: {short_name}")
        for pkg in data.get("packages", []):
            pkg_id = pkg.get("id", "")
            if short_name in pkg_id or pkg_id.endswith(f"/{short_name}"):
                return base_url + pkg.get("location"), "Mirrored Strip"
        
        # Even more fuzzy: check if any part of the short_name matches a package
        parts = short_name.split("-")
        for part in parts:
            if len(part) < 4: continue
            for pkg in data.get("packages", []):
                pkg_id = pkg.get("id", "")
                if pkg_id.endswith(f"/{part}"):
                    return base_url + pkg.get("location"), f"Part Match ({part})"

    # Priority 2: Substring match (more aggressive)
    for pkg in data.get("packages", []):
        pkg_id = pkg.get("id", "")
        if repo_name in pkg_id or (len(repo_name) > 5 and pkg_id.split("/")[-1] in repo_name):
            return base_url + pkg.get("location"), "Aggressive Fuzzy"
            
    return None, "No Match"

async def main():
    test_images = [
        "registry.rancher.com/rancher/mirrored-grafana-grafana-image-renderer:3.10.5",
        "registry.rancher.com/rancher/rancher:v2.9.2"
    ]
    
    # Test Resolution
    for img in test_images:
        url, meth = await resolve_vex_url(img)
        print(f"RESOLUTION RESULT for {img}: URL={url}, Method={meth}")

if __name__ == "__main__":
    asyncio.run(main())
