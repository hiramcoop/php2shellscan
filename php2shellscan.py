#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shellscan.py
===================
Comprueba qué servidores anuncian una versión de PHP afectada por:
    - CVE-2026-109618 (Out-of-memory / corrupción de memoria)
    - CVE-2026-109619 (Estado global obsoleto -> use-after-free)

Lee la versión de PHP que expone el servicio web en sus cabeceras HTTP
(X-Powered-By / Server) y la compara contra la tabla de versiones corregidas.
NO lanza exploits ni envía payloads: solo hace una petición normal y mira las
cabeceras. Es no destructivo.
 
Uso:
    # Una IP o una URL:
    python3 php2shellscan.py 192.168.1.10
    python3 php2shellscan.py https://tienda.midominio.com
 
    # Varias de golpe:
    python3 php2shellscan.py 192.168.1.10 10.0.0.5 https://web.midominio.com
 
    # Guardar informe:
    python3 php2shellscan.py 192.168.1.10 --csv informe.csv
 
Nota: muchos servidores ocultan la versión en las cabeceras por seguridad.
Si sale DESCONOCIDO no significa que esté a salvo, solo que no la anuncia.

Verifica los umbrales de abajo contra el aviso oficial de PHP
(https://www.php.net/ChangeLog-8.php) y ajústalos si cambian.
"""
 
import argparse
import concurrent.futures as cf
import csv
import re
import ssl
import sys
import urllib.error
import urllib.request
 
# ---------------------------------------------------------------------------
# CONFIGURACIÓN: primera versión CORREGIDA por rama.
# Cualquier versión de esa rama ESTRICTAMENTE MENOR es vulnerable.
# ---------------------------------------------------------------------------
FIXED_VERSIONS = {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12",
}
 
# Ramas < 8.2 no tienen parche publicado (EOL). True = marcarlas como afectadas.
OLD_BRANCHES_VULNERABLE = True
OLDEST_AFFECTED_BRANCH = (5, 4)
 
CVES = "CVE-2026-109618, CVE-2026-109619"
VERSION_RE = re.compile(r"PHP[/\s]+(\d+)\.(\d+)\.(\d+)")
 
 
# ---------------------------------------------------------------------------
# Comparación de versiones
# ---------------------------------------------------------------------------
def parse_version(text):
    m = VERSION_RE.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None
 
 
def verdict_for_version(ver):
    if ver is None:
        return ("DESCONOCIDO", "el servidor no anuncia la versión de PHP")
 
    branch = f"{ver[0]}.{ver[1]}"
    vstr = ".".join(str(x) for x in ver)
 
    if branch in FIXED_VERSIONS:
        fixed = tuple(int(x) for x in FIXED_VERSIONS[branch].split("."))
        if ver < fixed:
            return ("AFECTADO", f"{vstr} < {FIXED_VERSIONS[branch]} (corregida)")
        return ("NO AFECTADO", f"{vstr} >= {FIXED_VERSIONS[branch]}")
 
    if (ver[0], ver[1]) < OLDEST_AFFECTED_BRANCH:
        return ("NO AFECTADO", f"rama {branch} anterior al rango afectado")
 
    max_branch = max(tuple(int(x) for x in b.split(".")) for b in FIXED_VERSIONS)
    if (ver[0], ver[1]) > max_branch:
        return ("NO AFECTADO", f"rama {branch} posterior a las afectadas (revisa aviso)")
 
    if OLD_BRANCHES_VULNERABLE:
        return ("AFECTADO", f"rama {branch} sin parche publicado (EOL) — actualiza de rama")
    return ("DESCONOCIDO", f"rama {branch} sin umbral definido — revisa manualmente")
 
 
def combine_verdicts(verdicts):
    order = {"AFECTADO": 0, "DESCONOCIDO": 1, "NO AFECTADO": 2}
    if not verdicts:
        return "DESCONOCIDO"
    return sorted(verdicts, key=lambda s: order.get(s, 1))[0]
 
 
# ---------------------------------------------------------------------------
# Detección por cabeceras HTTP
# ---------------------------------------------------------------------------
def fetch_headers(url, timeout):
    """Intenta HEAD y, si no da cabeceras de versión, GET. Sin verificar cert."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # no fallar por certificados autofirmados
 
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(
                url, method=method,
                headers={"User-Agent": "php-version-scan/2.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.headers, None
        except urllib.error.HTTPError as e:
            return e.headers, None  # 4xx/5xx igual traen cabeceras útiles
        except Exception as e:  # noqa: BLE001
            last = f"{e}"
    return None, last
 
 
def scan_target(target, timeout=10):
    """target puede ser una IP, un host o una URL completa."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        urls = [target]
    else:
        # Sin esquema: prueba primero https y luego http.
        urls = ["https://" + target, "http://" + target]
 
    headers = None
    err = "sin respuesta"
    for u in urls:
        headers, err = fetch_headers(u, timeout)
        if headers is not None:
            break
 
    rows = []
    if headers is None:
        rows.append({"target": target, "fuente": "-", "version": "-",
                     "estado": "DESCONOCIDO", "detalle": f"http: {err}"})
        return rows, "DESCONOCIDO"
 
    verdicts = []
    for key in ("X-Powered-By", "Server"):
        val = headers.get(key, "")
        ver = parse_version(val)
        if ver:
            estado, detalle = verdict_for_version(ver)
            verdicts.append(estado)
            rows.append({"target": target, "fuente": f"{key}: {val.strip()}",
                         "version": ".".join(str(x) for x in ver),
                         "estado": estado, "detalle": detalle})
 
    if not rows:
        rows.append({"target": target, "fuente": "-", "version": "-",
                     "estado": "DESCONOCIDO",
                     "detalle": "el servidor no expone la versión en cabeceras"})
        return rows, "DESCONOCIDO"
 
    return rows, combine_verdicts(verdicts)
 
 
# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
COLORS = {"AFECTADO": "\033[91m", "NO AFECTADO": "\033[92m",
          "DESCONOCIDO": "\033[93m", "_end": "\033[0m"}
 
 
def color(text, estado, use_color):
    return f"{COLORS.get(estado, '')}{text}{COLORS['_end']}" if use_color else text
 
 
def main():
    ap = argparse.ArgumentParser(
        description="Escáner por versión (cabeceras HTTP) para %s." % CVES)
    ap.add_argument("hosts", nargs="+", help="una o más IPs o URLs a comprobar")
    ap.add_argument("--csv", help="guardar informe CSV en esta ruta")
    ap.add_argument("--timeout", type=int, default=10, help="segundos por petición")
    ap.add_argument("--workers", type=int, default=10, help="hilos concurrentes")
    ap.add_argument("--no-color", action="store_true", help="salida sin color")
    args = ap.parse_args()
 
    use_color = (not args.no_color) and sys.stdout.isatty()
 
    print(f"# Escaneo por versión (HTTP) — {CVES}")
    print(f"# Objetivos: {len(args.hosts)}")
    print(f"# Umbrales (primera versión corregida): {FIXED_VERSIONS}\n")
 
    all_rows = []
    summary = {"AFECTADO": 0, "NO AFECTADO": 0, "DESCONOCIDO": 0}
 
    with cf.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(scan_target, h, args.timeout): h for h in args.hosts}
        results = [f.result() for f in cf.as_completed(futs)]
 
    for rows, overall in results:
        all_rows.extend(rows)
        summary[overall] = summary.get(overall, 0) + 1
        print(color(f"[{overall}] {rows[0]['target']}", overall, use_color))
        for r in rows:
            print(f"      - {r['fuente']:<40} {r['version']:<10} {r['detalle']}")
 
    print("\n# Resumen")
    for estado in ("AFECTADO", "NO AFECTADO", "DESCONOCIDO"):
        print(color(f"  {estado}: {summary[estado]}", estado, use_color))
 
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(
                fh, fieldnames=["target", "fuente", "version", "estado", "detalle"])
            w.writeheader()
            w.writerows(all_rows)
        print(f"\n# Informe CSV guardado en: {args.csv}")
 
    if summary["AFECTADO"]:
        sys.exit(2)
    if summary["DESCONOCIDO"]:
        sys.exit(1)
    sys.exit(0)
 
 
if __name__ == "__main__":
    main()