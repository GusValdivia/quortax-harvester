"""
Quortax Hub — theHarvester Microservice
FastAPI wrapper around theHarvester for OSINT collection.
Endpoints consumed by the Quortax Hub backend.
"""

import asyncio
import subprocess
import json
import os
import tempfile
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="Quortax Harvester",
    description="OSINT microservice — subdomains, emails, IPs via theHarvester",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str                          # domain to scan, e.g. "empresa.com.br"
    sources: Optional[str] = "all"      # crtsh,dnsdumpster,hackertarget,etc.
    limit: Optional[int] = 100

class ScanResult(BaseModel):
    target: str
    subdomains: list[str]
    emails: list[str]
    ips: list[str]
    interesting_urls: list[str]
    sources_used: list[str]
    error: Optional[str] = None

# ─── Safe sources that don't require API keys ─────────────────────────────────
DEFAULT_SOURCES = [
    "crtsh",
    "dnsdumpster",
    "hackertarget",
    "rapiddns",
    "otx",
    "threatminer",
    "urlscan",
    "certspotter",
]

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "quortax-harvester", "version": "1.0.0"}

@app.post("/scan", response_model=ScanResult)
async def run_scan(req: ScanRequest):
    """
    Run theHarvester against a target domain.
    Returns subdomains, emails, IPs found via OSINT.
    """
    target = req.target.strip().lower()
    if not target or len(target) < 3:
        raise HTTPException(status_code=400, detail="Target inválido")

    # Use safe default sources if "all" requested
    sources = DEFAULT_SOURCES if req.sources == "all" else req.sources.split(",")
    sources_str = ",".join(sources)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        output_file = f.name

    try:
        cmd = [
            "theHarvester",
            "-d", target,
            "-b", sources_str,
            "-l", str(req.limit),
            "-f", output_file.replace(".json", ""),  # theHarvester adds .json
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            return ScanResult(
                target=target,
                subdomains=[], emails=[], ips=[], interesting_urls=[],
                sources_used=sources,
                error="Scan timeout após 120s"
            )

        # Parse JSON output
        subdomains, emails, ips, urls = [], [], [], []

        json_path = output_file.replace(".json", "") + ".json"
        if os.path.exists(json_path):
            with open(json_path) as jf:
                data = json.load(jf)
                subdomains = list(set(data.get("hosts", [])))
                emails = list(set(data.get("emails", [])))
                ips = list(set(data.get("ips", [])))
                urls = list(set(data.get("interesting_urls", [])))

        # Fallback: parse stdout if JSON is empty
        if not subdomains and not emails:
            output_text = stdout.decode("utf-8", errors="ignore")
            for line in output_text.splitlines():
                line = line.strip()
                if "." in line and not line.startswith("[") and not line.startswith("*"):
                    if "@" in line:
                        emails.append(line)
                    elif any(line.endswith(f".{target}") or line == target for _ in [None]):
                        subdomains.append(line)

        return ScanResult(
            target=target,
            subdomains=sorted(set(subdomains))[:200],
            emails=sorted(set(emails))[:100],
            ips=sorted(set(ips))[:100],
            interesting_urls=sorted(set(urls))[:50],
            sources_used=sources,
        )

    except Exception as e:
        return ScanResult(
            target=target,
            subdomains=[], emails=[], ips=[], interesting_urls=[],
            sources_used=sources,
            error=str(e)
        )
    finally:
        for path in [output_file, output_file.replace(".json", "") + ".json",
                     output_file.replace(".json", "") + ".xml"]:
            try:
                os.unlink(path)
            except Exception:
                pass

@app.get("/sources")
def list_sources():
    """List available OSINT sources (no API key required)"""
    return {"sources": DEFAULT_SOURCES}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
