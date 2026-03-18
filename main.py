"""
Quortax Hub — OSINT Microservice
Coleta passiva de subdomínios, e-mails e IPs via APIs públicas abertas.
Sem theHarvester — dependências 100% PyPI, sem instalação via GitHub.
"""

import asyncio
import re
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import httpx

app = FastAPI(
    title="Quortax OSINT",
    description="Reconhecimento passivo: subdomínios, e-mails, IPs via fontes abertas",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    sources: Optional[str] = "all"
    limit: Optional[int] = 100

class ScanResult(BaseModel):
    target: str
    subdomains: list[str]
    emails: list[str]
    ips: list[str]
    interesting_urls: list[str]
    sources_used: list[str]
    error: Optional[str] = None

# ─── OSINT Sources ────────────────────────────────────────────────────────────

async def query_crtsh(domain: str, client: httpx.AsyncClient) -> list[str]:
    """Certificate Transparency logs via crt.sh"""
    try:
        r = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            names = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if domain in n and n != domain:
                        names.add(n.lower())
            return list(names)
    except Exception:
        pass
    return []

async def query_hackertarget(domain: str, client: httpx.AsyncClient) -> list[str]:
    """HackerTarget subdomain finder"""
    try:
        r = await client.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:50]:
            subs = set()
            for line in r.text.strip().split("\n"):
                parts = line.split(",")
                if parts and domain in parts[0]:
                    subs.add(parts[0].strip().lower())
            return list(subs)
    except Exception:
        pass
    return []

async def query_rapiddns(domain: str, client: httpx.AsyncClient) -> list[str]:
    """RapidDNS subdomain lookup"""
    try:
        r = await client.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            pattern = rf'[\w\-\.]+\.{re.escape(domain)}'
            matches = re.findall(pattern, r.text)
            return list({m.lower() for m in matches if m != domain})
    except Exception:
        pass
    return []

async def query_urlscan(domain: str, client: httpx.AsyncClient) -> tuple[list[str], list[str]]:
    """urlscan.io for subdomains and interesting URLs"""
    subs, urls = set(), set()
    try:
        r = await client.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
            timeout=15,
            headers={"User-Agent": "QuortaxOSINT/2.0"}
        )
        if r.status_code == 200:
            data = r.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                sub = page.get("domain", "")
                if sub and domain in sub:
                    subs.add(sub.lower())
                url = page.get("url", "")
                if url and domain in url:
                    urls.add(url)
    except Exception:
        pass
    return list(subs), list(urls)

async def query_emailformat(domain: str, client: httpx.AsyncClient) -> list[str]:
    """Email pattern discovery via email-format.com"""
    emails = set()
    try:
        r = await client.get(
            f"https://www.email-format.com/d/{domain}/",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            found = re.findall(r'[\w\.\-]+@' + re.escape(domain), r.text)
            emails.update(f.lower() for f in found)
    except Exception:
        pass
    return list(emails)

async def query_ips(subdomains: list[str], client: httpx.AsyncClient) -> list[str]:
    """Resolve IPs via HackerTarget DNS lookup"""
    ips = set()
    # Limit to first 10 subdomains to avoid rate limiting
    for sub in subdomains[:10]:
        try:
            r = await client.get(
                f"https://api.hackertarget.com/dnslookup/?q={sub}",
                timeout=10
            )
            if r.status_code == 200:
                found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r.text)
                ips.update(found)
        except Exception:
            pass
    return list(ips)

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "quortax-osint", "version": "2.0.0"}

@app.get("/sources")
def list_sources():
    return {"sources": ["crtsh", "hackertarget", "rapiddns", "urlscan", "emailformat"]}

@app.post("/scan", response_model=ScanResult)
async def run_scan(req: ScanRequest):
    target = req.target.strip().lower().lstrip("www.")
    if not target or len(target) < 3:
        return ScanResult(
            target=target, subdomains=[], emails=[], ips=[],
            interesting_urls=[], sources_used=[], error="Target inválido"
        )

    subdomains: set[str] = set()
    emails: set[str] = set()
    ips: set[str] = set()
    urls: set[str] = set()
    sources_used = []

    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Run all sources in parallel
        results = await asyncio.gather(
            query_crtsh(target, client),
            query_hackertarget(target, client),
            query_rapiddns(target, client),
            query_urlscan(target, client),
            query_emailformat(target, client),
            return_exceptions=True
        )

        crtsh_subs, ht_subs, rapid_subs, urlscan_result, email_result = results

        if not isinstance(crtsh_subs, Exception) and crtsh_subs:
            subdomains.update(crtsh_subs); sources_used.append("crtsh")

        if not isinstance(ht_subs, Exception) and ht_subs:
            subdomains.update(ht_subs); sources_used.append("hackertarget")

        if not isinstance(rapid_subs, Exception) and rapid_subs:
            subdomains.update(rapid_subs); sources_used.append("rapiddns")

        if not isinstance(urlscan_result, Exception) and urlscan_result:
            us_subs, us_urls = urlscan_result
            subdomains.update(us_subs); urls.update(us_urls)
            if us_subs or us_urls: sources_used.append("urlscan")

        if not isinstance(email_result, Exception) and email_result:
            emails.update(email_result); sources_used.append("emailformat")

        # Resolve IPs from discovered subdomains
        if subdomains:
            ip_list = await query_ips(list(subdomains)[:10], client)
            ips.update(ip_list)

    limit = req.limit or 100
    return ScanResult(
        target=target,
        subdomains=sorted(subdomains)[:limit],
        emails=sorted(emails)[:50],
        ips=sorted(ips)[:50],
        interesting_urls=sorted(urls)[:50],
        sources_used=list(set(sources_used)),
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
