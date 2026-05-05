import requests
import modules.system as mSystem
import time
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from config.settings import config
from core.colores_terminal import print_c, mostrar_subtitulos

# Librería CVSS, debería estar instalada, pero por si acaso lo ponemos en un try para que el programa funcione incluso sin la librería
try:
    from cvss import CVSS2, CVSS3
    LIBRERIA_CVSS = True
except ImportError:
    LIBRERIA_CVSS = False



############# Caches #########################################################################################################################
# Guardamos el score de una CVE para no repetir peticiones a la API y ahorrar tiempo
cache_detalles_osv   = {}

# Guardamos si un CVE está parcheado o no, de esta forma nos evitamos repetir peticiones a la API y ahorramos tiempo
cache_ubuntu_tracker = {}

# cargado una vez en memoria, es un diccionario de 50 MB que tiene todos los parches de seguridad del ecosistema Debian, no hacemos como en Ubuntu ya que no hay una API
cache_debian_tracker = {} 

# Diseñado para optimizar el código, protege los hilos en condiciones de carrera (lectura y escritura simultanea)
_cache_lock          = threading.Lock()

# También para condiciones de carrera, pero en este caso se asegura de que un único hilo trate de descargar el diccionario de Debian
_debian_tracker_lock = threading.Lock()

# Controla si se ha descargado el diccionario de Debian
_debian_cargado      = False

# Variables globales
OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL   = "https://api.osv.dev/v1/vulns/{}"
UBUNTU_TRACKER = "https://ubuntu.com/security/cves/{}.json"
DEBIAN_TRACKER = "https://security-tracker.debian.org/tracker/data/json"
TAM_LOTE       = 100
MAX_REINTENTOS = 3
TIMEOUT        = 15


# Diccionario que contiene varias distros que son basadas en Debian, por lo que el escaner es aplicable a ellas
FAMILIAS_DEBIAN = {
    "debian", "ubuntu", "linuxmint", "mint", "pop", "elementary",
    "zorin", "kali", "parrot", "mx", "mxlinux", "lmde", "deepin",
    "raspbian", "armbian", "peppermint", "bodhi", "tails"
}









############ Detección de distro #####################################################################################################################################
def detectar_info_distro():
    """
    Lee /etc/os-release y determina:
      - Si la distro es de la familia Debian/Ubuntu
      - Qué ecosistemas usar en OSV
      - Si usar el Ubuntu Security Tracker (y con qué codename)
      - Si usar el Debian Security Tracker
      - Qué tipo de tracker aplica ('ubuntu', 'debian', None)
    """
    info = {
        "ID": "",
        "ID_LIKE": "",
        "VERSION_CODENAME": "",
        "UBUNTU_CODENAME": "",  # Aparece en los SOs deribados de Ubuntu
    }

    # Leemos el archivo release, donde aparece la info del SO (similar a info_sis), para evitar problemas eliminamos espacios, dividimos el string en 2 partes y nos quedamos
    # con la segunda (donde aparece el valor para cada atributo y finalmente ponemos todo en minúsculas
    try:
        with open("/etc/os-release") as f:
            for line in f:
                for clave in info:
                    if line.startswith(f"{clave}="):
                        info[clave] = line.strip().split("=", 1)[1].strip('"').lower()
    except Exception:
        pass

    distro_id = info["ID"]
    # ID_LIKE puede tener varios valores: "ubuntu debian", "debian ubuntu"...
    id_like = set(info["ID_LIKE"].split())
    codename = info["VERSION_CODENAME"]
    ubuntu_code = info["UBUNTU_CODENAME"]

    todas_ids = {distro_id} | id_like

    # Comprobar si pertenece a la familia Debian
    es_familia_debian = bool(todas_ids & FAMILIAS_DEBIAN)

    if not es_familia_debian:
        # Distro no reconocida como Debian/Ubuntu — no usamos trackers
        return [], None, None, None

    # Determinar si es rama Ubuntu o rama Debian pura
    es_ubuntu = "ubuntu" in todas_ids
    es_debian  = "debian" in todas_ids and not es_ubuntu

    # Ecosistemas OSV
    if es_ubuntu:
        ecosistemas = ["Ubuntu", "Debian"]
    else:
        ecosistemas = ["Debian"]

    # Codename para Ubuntu Security Tracker
    # Mint y derivadas exponen UBUNTU_CODENAME con el codename real de Ubuntu base
    codename_ubuntu = ubuntu_code or (codename if es_ubuntu else None)

    # Tipo de tracker a usar
    if es_ubuntu and codename_ubuntu:
        tipo_tracker = "ubuntu"
        codename_tracker = codename_ubuntu
    elif es_debian and codename:
        tipo_tracker = "debian"
        codename_tracker = codename
    else:
        tipo_tracker = None
        codename_tracker = None

    return ecosistemas, tipo_tracker, codename_tracker, distro_id


ECOSISTEMAS_SO, TIPO_TRACKER, CODENAME_TRACKER, DISTRO_ID = detectar_info_distro()



####################################################################################################################################################################
########### Security tracker Ubuntu ################################################################################################################################
####################################################################################################################################################################

def cve_parcheado_ubuntu(cve_id, nombre_paquete):
    """
    Consulta el Ubuntu Security Tracker para un CVE concreto.

    Retorna:
        True  → parcheado en esta release (descartar)
        False → sigue vulnerable
        None  → sin información (conservar por precaución)
    """
    clave = f"{cve_id}::{nombre_paquete}"
    with _cache_lock:
        if clave in cache_ubuntu_tracker:
            return cache_ubuntu_tracker[clave]

    resultado = None
    try:
        r = requests.get(UBUNTU_TRACKER.format(cve_id), timeout=TIMEOUT)

        if r.status_code == 200:
            for pkg_info in r.json().get("packages", []):
                if pkg_info.get("name") != nombre_paquete:
                    continue
                for s in pkg_info.get("statuses", []):
                    if s.get("release_codename") != CODENAME_TRACKER:
                        continue
                    status = s.get("status", "")
                    if status in ("released", "not-affected", "ignored"):
                        resultado = True
                    elif status in ("needed", "deferred", "pending"):
                        resultado = False
                    break
                if resultado is not None:
                    break

    except Exception:
        pass

    with _cache_lock:
        cache_ubuntu_tracker[clave] = resultado

    return resultado



####################################################################################################################################################################
########### Security tracker Debian ################################################################################################################################
####################################################################################################################################################################


def cargar_debian_tracker():
    """
    Descarga el JSON completo del Debian Security Tracker una sola vez
    y lo guarda en cache_debian_tracker.

    Estructura del JSON de Debian:
    {
      "package_name": {
        "CVE-XXXX-XXXX": {
          "releases": {
            "bookworm": {
              "status": "resolved" | "open" | "undetermined",
              "fixed_version": "1.2.3"
            }
          }
        }
      }
    }
    """
    global _debian_cargado

    with _debian_tracker_lock:
        if _debian_cargado:
            return True

        try:
            print_c("[i] Descargando Debian Security Tracker (~50MB), espere...")
            r = requests.get(DEBIAN_TRACKER, timeout=60)

            if r.status_code != 200:
                print_c(f"[WARN] Debian Security Tracker devolvió {r.status_code}")
                return False

            datos = r.json()

            # Reindexar por CVE → paquete para búsquedas O(1)
            # cache_debian_tracker[cve_id][pkg_name] = status_info
            for pkg_name, cves in datos.items():
                for cve_id, cve_info in cves.items():
                    if cve_id not in cache_debian_tracker:
                        cache_debian_tracker[cve_id] = {}
                    releases = cve_info.get("releases", {})
                    cache_debian_tracker[cve_id][pkg_name] = releases

            _debian_cargado = True
            print_c(f"[i] Debian Security Tracker cargado ({len(cache_debian_tracker)} CVEs indexados)")
            return True

        except Exception as e:
            print_c(f"[WARN] No se pudo cargar el Debian Security Tracker: {e}")
            return False


def cve_parcheado_debian(cve_id, nombre_paquete):
    """
    Consulta el Debian Security Tracker (ya cargado en memoria).

    Retorna:
        True  → resuelto en esta release (descartar)
        False → sigue abierto
        None  → sin información (conservar por precaución)
    """
    if not _debian_cargado:
        return None

    paquetes = cache_debian_tracker.get(cve_id)
    if not paquetes:
        return None

    releases = paquetes.get(nombre_paquete)
    if not releases:
        return None

    info_release = releases.get(CODENAME_TRACKER)
    if not info_release:
        return None

    status = info_release.get("status", "")

    if status in ("resolved", "not-affected"):
        return True
    if status in ("open", "undetermined"):
        return False

    return None


# -------------------------------
# DISPATCHER DE TRACKER
# -------------------------------

def cve_parcheado(cve_id, nombre_paquete):
    """
    Punto de entrada único para comprobar si un CVE está parcheado.
    Delega al tracker correspondiente según la distro detectada.
    """
    if TIPO_TRACKER == "ubuntu":
        return cve_parcheado_ubuntu(cve_id, nombre_paquete)
    if TIPO_TRACKER == "debian":
        return cve_parcheado_debian(cve_id, nombre_paquete)
    return None









####################################################################################################################################################################
########### Operaciones OSV.dev ####################################################################################################################################
####################################################################################################################################################################


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
                "package": {"name": p["name"], "ecosystem": ecosistema},
                "version": p["version"]
            })
            meta.append({**p, "ecosystem": ecosistema})
    return consultas, meta


# -------------------------------
# PROCESADO DE RESULTADOS
# -------------------------------

def procesar_resultados_batch(resultados_osv, paquetes_meta, cfg_vulns, sesion):
    min_cvss        = float(cfg_vulns.get("min_cvss_score", 0.0))
    lista_ignorados = set(cfg_vulns.get("ignorar", []))
    usar_tracker    = TIPO_TRACKER is not None

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

            # Capa 1: versión fixed en OSV
            if pkg["type"] == "System (APT)":
                if es_falso_positivo_so(pkg["version"], v_full):
                    continue

            # Filtro CVSS
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

                # Capa 2: Security Tracker (Ubuntu o Debian según distro)
                if usar_tracker and pkg["type"] == "System (APT)":
                    if cve_parcheado(cve_id, pkg["name"]) is True:
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
    data   = post_con_reintentos(sesion, OSV_BATCH_URL, {"queries": consultas_lote})
    if not data:
        return []
    return procesar_resultados_batch(data.get("results", []), meta_lote, cfg_vulns, sesion)











######### ES

def escanear_vulnerabilidades(paquetes_apt, paquetes_pip):
    cfg_vulns = config.get("vulnerabilities", {})

    consultas_apt, meta_apt = construir_consultas_apt(paquetes_apt)

    consultas_pip = [
        {"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]}
        for p in paquetes_pip
    ]

    todas_consultas = consultas_apt + consultas_pip
    todo_meta       = meta_apt + paquetes_pip

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










########### ESCANER ###############################################################################################################################################

def ESCANER_vulnerabilidades(verbose):
    mostrar_subtitulos("Vulnerabilidades")
    print("")
    print_c("[+] Iniciando módulo de escaneo de vulnerabilidades")

    if not ECOSISTEMAS_SO:
        print_c("[!] Distro no compatible (no es de la familia Debian/Ubuntu). Módulo desactivado.")
        return {"paquetes": {"apt": 0, "pip": 0}, "vulns": []}

    print_c(f"[i] Distro detectada: {DISTRO_ID}")
    print_c(f"[i] Ecosistemas OSV: {', '.join(ECOSISTEMAS_SO)}")

    # Inicializar tracker según distro
    if TIPO_TRACKER == "ubuntu":
        print_c(f"[i] Ubuntu Security Tracker activo (codename: {CODENAME_TRACKER})")
    elif TIPO_TRACKER == "debian":
        print_c(f"[i] Debian Security Tracker activo (codename: {CODENAME_TRACKER})")
        cargar_debian_tracker()  # descarga única antes del escaneo
    else:
        print_c("[!] No hay Security Tracker disponible para esta distro")

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
        "paquetes": {"apt": len(p_apt), "pip": len(p_pip)},
        "vulns": resultados
    }