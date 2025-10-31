#!/usr/bin/env python3
import sys
import subprocess
import importlib
import os

# ======================= Banner ==========================
def show_banner():
    banner = [
        "              _,.-------.,_",
        "            ,;~'          '~;,",
        "          ,;                ;,",
        "          ;                   ;",
        "        ,'                    ',",
        "       ,;                      ;,",
        "       ; ;      .        .      ; ;",
        "       | ;    ______      ______    ; |",
        "       |  `/~\"      \" . \"      \"~\\'  |",
        "       |  ~ ,-~~~^~, | ,~^~~~-, ~  |",
        "        |  |        }:{        |  |",
        "        |  l        / | \\        !  |",
        "        .~ (__,.--\" .^. \"--.,__) ~.",
        "        |     ---;' / | \\ `;---      |",
        "          \\__.        \\/^\\/        .__/",
        "           V| \\                  / |V",
        "            | |T~\\___!___!___/~T| |",
        "            | |`IIII_I_I_I_IIII'| |",
        "            |  \\,III I I I III,/  |",
        "             \\    `~~~~~~~~~~'    /",
        "              \\    .        .    /",
        "               \\.    ^    .  /",
        "                 ^~._____.~^",
        "================================================================================",
        "              ☠️   A M A L I C I O U S   M I N D   ☠️",
        "--------------------------------------------------------------------------------",
        "                            coded by naveen",
        "================================================================================"
    ]
    print("\n".join(banner))
# ==========================================================


REQUIRED = ["aiohttp", "bs4"]

def ensure_packages(pkgs):
    missing = []
    for p in pkgs:
        try:
            importlib.import_module(p if p != "bs4" else "bs4")
        except ModuleNotFoundError:
            missing.append(p)
    if not missing:
        return
    print("\nMissing packages:", ", ".join(missing))
    print("Installing via pip...")
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + missing
    subprocess.check_call(cmd)
    print("Installed. Restarting script...\n")
    os.execv(sys.executable, [sys.executable] + sys.argv)


if __name__ == "__main__":
    show_banner()  # <<< Banner shows first
    ensure_packages(REQUIRED)

    import asyncio
    import aiohttp
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin, urldefrag, urlparse

    visited = set()

    async def fetch(session, url):
        try:
            async with session.get(url, timeout=10) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "text/html" in ct or "application/xhtml+xml" in ct:
                    return await resp.text(errors="ignore")
        except Exception:
            pass
        return None

    def extract_links(base_url, html):
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            try:
                joined = urljoin(base_url, href)
                joined, _ = urldefrag(joined)
                if joined.startswith("http"):
                    links.add(joined)
            except Exception:
                continue
        return links

    async def crawl(session, seed, max_depth=2, same_domain=True):
        queue = [(seed, 0)]
        base_netloc = urlparse(seed).netloc
        while queue:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            print(url)
            html = await fetch(session, url)
            if not html:
                continue
            for link in extract_links(url, html):
                if same_domain and urlparse(link).netloc != base_netloc:
                    continue
                if link not in visited:
                    queue.append((link, depth + 1))

    async def main():
        seed = input("\nEnter URL (e.g. https://example.com): ").strip()
        try:
            depth = int(input("Max depth (default 2): ") or 2)
        except Exception:
            depth = 2
        async with aiohttp.ClientSession() as session:
            await crawl(session, seed, max_depth=depth, same_domain=True)
        print("\n--- Done ---")

    asyncio.run(main())
