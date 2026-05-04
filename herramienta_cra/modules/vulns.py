import requests
import modules.system as mSystem
import time
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from config.settings import config
from core.colores_terminal import print_c, mostrar_subtitulos

# Librería CVSS
try:
    from cvss import CVSS2, CVSS3
    LIBRERIA_CVSS = True
except ImportError:
    LIBRERIA_CVSS = False

# --- CACHÉS THREAD-SAFE ---
cache_detalles_osv  = {}
cache_ubuntu_tracker = {}   # cve_id → True (parcheado) / False (no parcheado) / None (desconocido)
_cache_lock         = threading.Lock()

OSV_BATCH_URL    = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL     = "https://api.osv.dev/v1/vulns/{}"
UBUNTU_TRACKER   = "https://ubuntu.com/security/cves/{}.json"
TAM_LOTE         = 100
MAX_REINTENTOS   = 3
TIMEOUT          = 15


# -------------------------------
# DETECCIÓN DE DISTRO
# -------------------------------

def detectar_ecosistema_so():
    try:
        with open("/etc/os-release") as f:
            contenido = f.read().lower()
        if "ubuntu" in contenido:
            return ["Ubuntu", "Debian"]
        if "debian" in contenido:
            return ["Debian"]
    except Exception:
        pass
    return ["Debian"]


def detectar_codename_ubuntu():
    """
    Extrae el codename de Ubuntu (ej: 'noble', 'jammy') desde /etc/os-release.
    Necesario para consultar el Ubuntu Security Tracker.
    """
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_CODENAME="):
                    return line.strip().split("=", 1)[1].strip('"').lower()
    except Exception:
        pass
    return None


ECOSISTEMAS_SO   = detectar_ecosistema_so()
UBUNTU_CODENAME  = detectar_codename_ubuntu()


# -------------------------------
# UBUNTU SECURITY TRACKER
# -------------------------------

def cve_parcheado_en_ubuntu(cve_id, nombre_paquete):
    """
    Consulta el Ubuntu Security Tracker para saber si un CVE está
    parcheado en la release actual del sistema.

    Retorna:
        True  → parcheado (falso positivo, descartar)
        False → NO parcheado (vulnerabilidad real)
        None  → no hay info suficiente (conservar por precaución)
    """
    if not UBUNTU_CODENAME:
        return None

    clave_cache = f"{cve_id}::{nombre_paquete}"
    with _cache_lock:
        if clave_cache in cache_ubuntu_tracker:
            return cache_ubuntu_tracker[clave_cache]

    resultado = None
    try:
        url = UBUNTU_TRACKER.format(cve_id)
        r = requests.get(url, timeout=TIMEOUT)

        if r.status_code == 404:
            # CVE no conocido por Ubuntu → conservar por precaución
            resultado = None
        elif r.status_code == 200:
            data = r.json()
            paquetes_afectados = data.get("packages", [])

            for pkg_info in paquetes_afectados:
                if pkg_info.get("name") != nombre_paquete:
                    continue

                statuses = pkg_info.get("statuses", [])
                for s in statuses:
                    if s.get("release_codename") != UBUNTU_CODENAME:
                        continue

                    status = s.get("status", "")

                    # "released" → Ubuntu publicó el fix → es falso positivo
                    # "not-affected" → Ubuntu considera que no aplica
                    if status in ("released", "not-affected", "ignored"):
                        resultado = True
                        break

                    # "needed", "deferred", "pending" → sigue vulnerable
                    if status in ("needed", "deferred", "pending"):
                        resultado = False
                        break

                if resultado is not None:
                    break

    except Exception:
        resultado = None

    with _cache_lock:
        cache_ubuntu_tracker[clave_cache] = resultado

    return resultado


# -------------------------------
# UTILIDADES
# -------------------------------

def comparar_versiones_nativa(v_instalada, v_fixed):
    try:
        import apt_pkg
        apt_pkg.init_system()
        return apt_pkg.version_compare(v_instalada, v_fixed) >= 0
    except Exception:
        res = subprocess.run(
            ['dpkg', '--compare-versions', v_instalada, 'ge', v_fixed],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0


def parse_vector(data):
    """Extrae score CVSS desde datos OSV de forma robusta."""
    if "severity" in data:
        for sev in data["severity"]:
            score = sev.get("score")
            if isinstance(score, (int, float)):
                return float(score)
            if isinstance(score, str) and LIBRERIA_CVSS:
                try:
                    if "CVSS:3" in score:
                        return CVSS3(score).scores()[0]
                    if "CVSS:2" in score:
                        return CVSS2(score).scores()[0]
                except Exception:
                    pass

    db = data.get("database_specific", {})
    try:
        if "nvd_cvss3" in db:
            return float(db["nvd_cvss3"]["cvssV3"]["baseScore"])
    except Exception:
        pass
    try:
        if "cvss" in db:
            return float(db["cvss"]["score"])
    except Exception:
        pass

    return None


def obtener_score_con_cache(vid, v_data, sesion):
    with _cache_lock:
        if vid in cache_detalles_osv:
            return cache_detalles_osv[vid]

    score = parse_vector(v_data)

    if score is None:
        try:
            r = sesion.get(OSV_VULN_URL.format(vid), timeout=TIMEOUT)
            if r.status_code == 200:
                score = parse_vector(r.json())
        except Exception:
            pass

    resultado = {"score": score, "data": v_data}
    with _cache_lock:
        cache_detalles_osv[vid] = resultado

    return resultado


def obtener_cves_reales(v):
    """
    Extrae CVEs reales desde OSV.
    Normaliza DEBIAN-CVE- y UBUNTU-CVE- a CVE-.
    """
    cves = set()

    def normalizar(valor):
        if valor.startswith("CVE-"):
            return valor
        for prefijo in ("DEBIAN-CVE-", "UBUNTU-CVE-"):
            if valor.startswith(prefijo):
                return valor.replace(prefijo, "CVE-", 1)
        return None

    cve = normalizar(v.get("id", ""))
    if cve:
        cves.add(cve)

    for alias in v.get("aliases", []):
        cve = normalizar(alias)
        if cve:
            cves.add(cve)

    return list(cves)


def es_falso_positivo_so(version_instalada, vuln_data):
    """
    Primera capa: comprueba si la versión instalada ya supera la versión fixed
    indicada en OSV (rangos ECOSYSTEM/SEMVER).
    """
    for affected in vuln_data.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in r.get("events", []):
                if "fixed" in event:
                    if comparar_versiones_nativa(version_instalada, event["fixed"]):
                        return True
    return False


# -------------------------------
# PETICIÓN AL BATCH CON REINTENTOS
# -------------------------------

def post_con_reintentos(sesion, url, payload):
    for intento in range(MAX_REINTENTOS):
        try:
            r = sesion.post(url, json=payload, timeout=TIMEOUT)
            if r.status_code == 200:
                return r.json()
            if r.status_code < 500:
                print_c(f"[WARN] OSV devolvió {r.status_code}, lote descartado")
                return None
        except requests.exceptions.RequestException as e:
            print_c(f"[WARN] Intento {intento + 1}/{MAX_REINTENTOS} fallido: {e}")
        time.sleep(2 ** intento)
    print_c("[ERROR] Lote descartado tras agotar reintentos")
    return None


# -------------------------------
# CONSULTA MULTI-ECOSISTEMA (APT)
# -------------------------------

def construir_consultas_apt(paquetes_apt):
    consultas = []
    meta = []

    for p in paquetes_apt:
        for ecosistema in ECOSISTEMAS_SO:
            consultas.append({
                "package": {
                    "name":      p["name"],
                    "ecosystem": ecosistema
                },
                "version": p["version"]
            })
            meta.append({**p, "ecosystem": ecosistema})

    return consultas, meta


# -------------------------------
# PROCESADO DE RESULTADOS
# -------------------------------

def procesar_resultados_batch(resultados_osv, paquetes_meta, cfg_vulns, sesion):
    """
    Procesa la respuesta del batch de OSV y devuelve hallazgos.
    Aplica dos capas de filtrado para paquetes APT en Ubuntu:
      1. Comparación de versión fixed en OSV
      2. Consulta al Ubuntu Security Tracker
    """
    min_cvss        = float(cfg_vulns.get("min_cvss_score", 0.0))
    lista_ignorados = set(cfg_vulns.get("ignorar", []))
    usar_tracker    = bool(UBUNTU_CODENAME and "Ubuntu" in ECOSISTEMAS_SO)

    acumulador = {}

    for index, res in enumerate(resultados_osv):
        if "vulns" not in res:
            continue

        pkg   = paquetes_meta[index]
        clave = pkg["name"]

        if clave not in acumulador:
            acumulador[clave] = {
                "paquete":     pkg["name"],
                "version":     pkg["version"],
                "tipo":        pkg["type"],
                "cves_vistos": set(),
                "cves":        []
            }

        for v in res["vulns"]:
            cves_reales = obtener_cves_reales(v)
            if not cves_reales:
                continue

            vid     = v["id"]
            cached  = obtener_score_con_cache(vid, v, sesion)
            v_full  = cached["data"]
            score_b = cached["score"]

            # --- Capa 1: versión fixed en OSV ---
            if pkg["type"] == "System (APT)":
                if es_falso_positivo_so(pkg["version"], v_full):
                    continue

            # --- Filtro CVSS ---
            if score_b is None:
                score_final = -1.0
            elif score_b < min_cvss:
                continue
            else:
                score_final = score_b

            for cve_id in cves_reales:
                if cve_id in lista_ignorados:
                    continue
                if cve_id in acumulador[clave]["cves_vistos"]:
                    continue

                # --- Capa 2: Ubuntu Security Tracker ---
                # Solo para paquetes APT en sistemas Ubuntu.
                # Si el tracker confirma que está parcheado → descartamos.
                # Si devuelve None (sin info) → conservamos por precaución.
                if usar_tracker and pkg["type"] == "System (APT)":
                    parcheado = cve_parcheado_en_ubuntu(cve_id, pkg["name"])
                    if parcheado is True:
                        continue

                acumulador[clave]["cves_vistos"].add(cve_id)
                acumulador[clave]["cves"].append({
                    "id":    cve_id,
                    "score": score_final
                })

    hallazgos = []
    for datos in acumulador.values():
        if datos["cves"]:
            hallazgos.append({
                "paquete":  datos["paquete"],
                "version":  datos["version"],
                "tipo":     datos["tipo"],
                "cves":     datos["cves"],
                "cantidad": len(datos["cves"])
            })

    return hallazgos


# -------------------------------
# HILO DE TRABAJO
# -------------------------------

def trabajador_lote(lote_info):
    consultas_lote, meta_lote, cfg_vulns = lote_info

    sesion = requests.Session()

    data = post_con_reintentos(sesion, OSV_BATCH_URL, {"queries": consultas_lote})
    if not data:
        return []

    resultados = data.get("results", [])
    return procesar_resultados_batch(resultados, meta_lote, cfg_vulns, sesion)


# -------------------------------
# ESCANEO PRINCIPAL
# -------------------------------

def escanear_vulnerabilidades(paquetes_apt, paquetes_pip):
    cfg_vulns = config.get("vulnerabilities", {})

    consultas_apt, meta_apt = construir_consultas_apt(paquetes_apt)

    consultas_pip = [
        {
            "package": {"name": p["name"], "ecosystem": "PyPI"},
            "version": p["version"]
        }
        for p in paquetes_pip
    ]
    meta_pip = paquetes_pip

    todas_consultas = consultas_apt + consultas_pip
    todo_meta       = meta_apt + meta_pip

    lotes = []
    for i in range(0, len(todas_consultas), TAM_LOTE):
        lotes.append((
            todas_consultas[i:i + TAM_LOTE],
            todo_meta[i:i + TAM_LOTE],
            cfg_vulns
        ))

    hallazgos = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for resultado in executor.map(trabajador_lote, lotes):
            hallazgos.extend(resultado)

    # Deduplicación final entre lotes
    vistos = {}
    for h in hallazgos:
        clave = h["paquete"]
        if clave not in vistos:
            vistos[clave] = h
        else:
            cves_existentes = {c["id"] for c in vistos[clave]["cves"]}
            for cve in h["cves"]:
                if cve["id"] not in cves_existentes:
                    vistos[clave]["cves"].append(cve)
                    vistos[clave]["cantidad"] += 1

    return list(vistos.values())


# -------------------------------
# FUNCIÓN PRINCIPAL
# -------------------------------

def ESCANER_vulnerabilidades(verbose):
    mostrar_subtitulos("Vulnerabilidades")
    print("")
    print_c("[+] Iniciando módulo de escaneo de vulnerabilidades")
    print_c(f"[i] Ecosistemas SO detectados: {', '.join(ECOSISTEMAS_SO)}")

    if UBUNTU_CODENAME:
        print_c(f"[i] Ubuntu codename detectado: {UBUNTU_CODENAME} — activando Ubuntu Security Tracker")
    else:
        print_c("[!] No se pudo detectar el codename de Ubuntu, se omite el Ubuntu Security Tracker")

    if not LIBRERIA_CVSS:
        print_c("[!] Instala cvss: pip install cvss")

    p_apt = mSystem.paquetes_instalados()
    p_pip = mSystem.paquetes_python()

    print_c(f"[i] Paquetes detectados del sistema (APT): {len(p_apt)}")
    print_c(f"[i] Paquetes detectados de python (PIP): {len(p_pip)}")
    print_c(f"[i] Consultas totales a OSV: {len(p_apt) * len(ECOSISTEMAS_SO) + len(p_pip)}")

    inicio     = time.time()
    resultados = escanear_vulnerabilidades(p_apt, p_pip)
    fin        = time.time()

    print_c(f"[+] Se han encontrado {len(resultados)} paquetes vulnerables")
    print_c(f"[i] Tiempo de escaneo: {fin - inicio:.2f}s")

    return {
        "paquetes": {
            "apt": len(p_apt),
            "pip": len(p_pip)
        },
        "vulns": resultados
    }