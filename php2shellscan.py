
#!/usr/bin/env python3
"""Escáner por versión para PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
 
Lee la versión de PHP que el servidor anuncia por HTTP (X-Powered-By / Server)
y la compara con las versiones corregidas. Solo detecta; no lanza exploits.
 
    python3 php2shellscan.py https://sitio.com 192.168.1.10
    python3 php2shellscan.py --input URLs.csv --csv informe.csv
 
Nota: si un servidor oculta la versión sale DESCONOCIDO (no implica estar a salvo).
Verifica los umbrales contra https://www.php.net/ChangeLog-8.php y edítalos si cambian.
"""
import argparse, concurrent.futures as cf, csv, re, ssl, sys, urllib.error, urllib.request
 
# Primera versión CORREGIDA por rama; cualquier versión menor es vulnerable.
FIXED = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
CVES = "CVE-2026-109618, CVE-2026-109619"
VER_RE = re.compile(r"PHP[/\s]+(\d+)\.(\d+)\.(\d+)")
COLORS = {"AFECTADO": "\033[91m", "NO AFECTADO": "\033[92m", "DESCONOCIDO": "\033[93m"}
 
 
def parse_version(text):
    m = VER_RE.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None
 
 
def verdict(ver):
    if not ver:
        return "DESCONOCIDO", "sin versión anunciada"
    branch, vs = f"{ver[0]}.{ver[1]}", ".".join(map(str, ver))
    if branch in FIXED:
        fx = tuple(int(x) for x in FIXED[branch].split("."))
        return ("AFECTADO", f"{vs} < {FIXED[branch]}") if ver < fx else ("NO AFECTADO", f"{vs} >= {FIXED[branch]}")
    top = max(tuple(int(x) for x in b.split(".")) for b in FIXED)
    if (ver[0], ver[1]) < (5, 4) or (ver[0], ver[1]) > top:
        return "NO AFECTADO", f"rama {branch} fuera del rango afectado"
    return "AFECTADO", f"rama {branch} sin soporte (EOL) — migra a 8.2+"
 
 
def worst(verdicts):
    for s in ("AFECTADO", "DESCONOCIDO", "NO AFECTADO"):
        if s in verdicts:
            return s
    return "DESCONOCIDO"
 
 
def load_targets(path):
    """Hosts/URLs de un archivo (admite CSV: 1ª columna). Ignora vacíos, # y encabezado."""
    heads = {"url", "urls", "host", "hosts", "target", "targets", "ip", "ips", "dominio"}
    out = []
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            first = line.split("#", 1)[0].split(",")[0].strip().strip("\"'")
            if first and first.lower() not in heads:
                out.append(first)
    return out
 
 
def scan(target, timeout):
    target = target.strip()
    urls = [target] if target.startswith(("http://", "https://")) else ["https://" + target, "http://" + target]
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # ignora cert autofirmado
 
    headers, err = None, "sin respuesta"
    for url in urls:
        for method in ("HEAD", "GET"):
            try:
                req = urllib.request.Request(url, method=method, headers={"User-Agent": "php2shell-scan"})
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    headers = r.headers
                break
            except urllib.error.HTTPError as e:
                headers = e.headers; break
            except Exception as e:
                err = str(e)
        if headers is not None:
            break
 
    rows = []
    if headers is not None:
        for key in ("X-Powered-By", "Server"):
            ver = parse_version(headers.get(key, ""))
            if ver:
                est, det = verdict(ver)
                rows.append({"target": target, "fuente": f"{key}: {headers.get(key).strip()}",
                             "version": ".".join(map(str, ver)), "estado": est, "detalle": det})
    if not rows:
        det = f"http: {err}" if headers is None else "el servidor no expone la versión"
        rows.append({"target": target, "fuente": "-", "version": "-", "estado": "DESCONOCIDO", "detalle": det})
    return rows, worst([r["estado"] for r in rows])
 
 
def main():
    ap = argparse.ArgumentParser(description=f"Escáner por versión (HTTP) para {CVES}.")
    ap.add_argument("hosts", nargs="*", help="IPs o URLs a comprobar")
    ap.add_argument("-i", "--input", help="archivo con hosts/URLs (admite CSV: 1ª columna)")
    ap.add_argument("--csv", help="guardar informe CSV de salida")
    ap.add_argument("--timeout", type=int, default=10, help="segundos por petición")
    ap.add_argument("--workers", type=int, default=10, help="peticiones concurrentes")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()
 
    targets = list(a.hosts) + (load_targets(a.input) if a.input else [])
    targets = list(dict.fromkeys(targets))  # únicos, en orden
    if not targets:
        ap.error("indica al menos una IP/URL, o un archivo con --input ARCHIVO")
 
    col = (not a.no_color) and sys.stdout.isatty()
    def paint(t, e): return f"{COLORS[e]}{t}\033[0m" if col else t
 
    print(f"# PHP2Shell — {CVES}\n# Objetivos: {len(targets)} | Umbrales: {FIXED}\n")
    all_rows, summary = [], {"AFECTADO": 0, "NO AFECTADO": 0, "DESCONOCIDO": 0}
    with cf.ThreadPoolExecutor(max_workers=max(1, a.workers)) as ex:
        results = [f.result() for f in cf.as_completed(
            [ex.submit(scan, t, a.timeout) for t in targets])]
 
    for rows, overall in results:
        all_rows += rows
        summary[overall] += 1
        print(paint(f"[{overall}] {rows[0]['target']}", overall))
        for r in rows:
            print(f"      - {r['fuente']:<40} {r['version']:<10} {r['detalle']}")
 
    print("\n# Resumen")
    for e in ("AFECTADO", "NO AFECTADO", "DESCONOCIDO"):
        print(paint(f"  {e}: {summary[e]}", e))
 
    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["target", "fuente", "version", "estado", "detalle"])
            w.writeheader(); w.writerows(all_rows)
        print(f"\n# Informe CSV: {a.csv}")
 
    sys.exit(2 if summary["AFECTADO"] else 1 if summary["DESCONOCIDO"] else 0)
 
 
if __name__ == "__main__":
    main()
