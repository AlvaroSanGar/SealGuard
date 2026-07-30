# SealGuard - Herramienta de Auditoria CRA
# Copyright (C) 2026 Alvaro Sanchez Garijo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
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
    info = {
        "ID": "",
        "ID_LIKE": "",
        "VERSION_CODENAME": "",
        "UBUNTU_CODENAME": "",  # Aparece en los SOs derivados de Ubuntu
    }

    # Leemos el archivo release, donde aparece la info del SO (similar a info_sis), para evitar problemas eliminamos espacios, dividimos el string en 2 partes y nos quedamos
    # con la segunda (donde aparece el valor para cada atributo), le quitamos las comillas al valor (si las tiene) y finalmente ponemos todo en minúsculas
    try:
        with open("/etc/os-release") as f:
            for line in f:
                for clave in info:
                    if line.startswith(f"{clave}="):
                        info[clave] = line.strip().split("=", 1)[1].strip('"').lower()
    except Exception:
        pass

    distro_id = info["ID"]
    id_like = set(info["ID_LIKE"].split())  # ID_LIKE puede tener varios valores: "ubuntu debian", "debian ubuntu"...
    codename = info["VERSION_CODENAME"]
    ubuntu_code = info["UBUNTU_CODENAME"]

    todas_ids = {distro_id} | id_like

    # Comprobar si pertenece a la familia Debian
    if not todas_ids & FAMILIAS_DEBIAN:
        # No es una distro cubierta en el código, así que no vamos a usar los trackers
        return [], None, None, None

    # Vamos a comprobar si la distro es una subversión de Ubuntu
    es_ubuntu = "ubuntu" in todas_ids
    es_debian  = "debian" in todas_ids and not es_ubuntu

    # Determinamos qué ecosistemas le vamos a pasar a la API de OSV
    if es_ubuntu:
        ecosistemas = ["Ubuntu", "Debian"]
    else:
        ecosistemas = ["Debian"]

    # Codename para Ubuntu Security Tracker
    # Las subversiones de Ubuntu tienen el parámetro codename_ubuntu en el archivo /etc/os-release, donde se indica la versión de ubuntu en la que se basan
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

def cve_parcheado_ubuntu(cve_id, nombre_paquete, version_instalada):
    # Creamos esta clave en vez de usar directamente el CVE, ya que un mismo CVE puede ir asociado a varios paquetes, por lo que debemos diferenciarlos
    clave = f"{cve_id}::{nombre_paquete}"

    # Como por motivos de optimización vamos a usar múltiples hilos en el sistema, por ello necesitamos usar el _cache_lock, para que no se produzcan errores de sincronización
    with _cache_lock:
        # Comprobamos que no se haya comprobado anteriormente el par CVE:paquete que estamos analizando, en cuyo caso no hacemos la consulta al tracker y simplemente devolvemos
        # el valor ya obtenido
        if clave in cache_ubuntu_tracker:
            return cache_ubuntu_tracker[clave]

    resultado = None
    try:
        # Metemos el CVE específico en la url de la petición y la realizamos (GET)
        r = requests.get(UBUNTU_TRACKER.format(cve_id), timeout=TIMEOUT)

        if r.status_code == 200:
            for pkg_info in r.json().get("packages", []):
                # Buscamos el nombre del paquete que le hemos mandado
                if pkg_info.get("name") != nombre_paquete:
                    continue

                for s in pkg_info.get("statuses", []):
                    # Una vez hemos hayado el paquete, buscamos la versión de Ubuntu en la que se basa el SO
                    if s.get("release_codename") != CODENAME_TRACKER:
                        continue
                    status = s.get("status", "")

                    ####### CATALOGAMOS LOS POSIBLES ESTADOS QUE PUEDE TENER EL PAQUETE #############################################################################
                    # Estos estados no dependen de versión, los descartamos directamente
                    if status in ("not-affected", "ignored"):
                        resultado = True

                    elif status == "released":
                        # Existe un parche que resuelve la vulnerabilidad, comprobamos si está instalado
                        version_fix = s.get("fixed_version", "")
                        if version_fix:
                            if comparar_versiones_nativa(version_instalada, version_fix):
                                # La versión instalada ya incluye el fix → falso positivo
                                resultado = True
                            else:
                                # El parche existe pero el usuario no lo ha instalado → sigue vulnerable
                                resultado = False
                        else:
                            # No hay versión de fix disponible, lo descartamos por precaución
                            resultado = True

                    # Es vulnerable y no ha sido parcheado aún, lo consideramos como peligroso
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
    # El tracker de Debian no es una API, es un archivo JSON, por ello debemos
    global _debian_cargado

    # Nos asseguramos de que solo haya 1 hilo que descargue el JSON, bloqueamos el resto
    with _debian_tracker_lock:
        if _debian_cargado:
            return True

        try:
            print_c("   [i] Descargando Debian Security Tracker (50MB), espere...")
            r = requests.get(DEBIAN_TRACKER, timeout=60)

            if r.status_code != 200:
                print_c(    "[!] Debian Security Tracker devolvió "+str(r.status_code))
                return False

            datos = r.json()

            # Debemos reorganizar el diccionario ya que en el JSON de debian la estructura es "paquete": [CVE1, CVE2], en nuestro caso como miramos por CVE, le damos
            # la vuelta, finalmente vemos el estado al igual que en Ubuntu
            for pkg_name, cves in datos.items():
                for cve_id, cve_info in cves.items():
                    if cve_id not in cache_debian_tracker:
                        cache_debian_tracker[cve_id] = {}
                    releases = cve_info.get("releases", {})
                    cache_debian_tracker[cve_id][pkg_name] = releases

            _debian_cargado = True
            print_c("   [Ok] Debian Security Tracker cargado ("+str(len(cache_debian_tracker))+" CVEs indexados)")
            return True

        except Exception as e:
            print_c("   [!] No se pudo cargar el Debian Security Tracker: "+str(e))
            return False


def cve_parcheado_debian(cve_id, nombre_paquete, version_instalada):
    # Vamos a hacer una serie de comprobaciones

    # No se ha cargado el tracker de Debian
    if not _debian_cargado:
        return None

    # El CVE no existe en el Tracker
    paquetes = cache_debian_tracker.get(cve_id)
    if not paquetes:
        return None

    # El CVE no afecta al paquete
    releases = paquetes.get(nombre_paquete)
    if not releases:
        return None

    # No hay información de nuestra versión (realese)
    info_release = releases.get(CODENAME_TRACKER)
    if not info_release:
        return None

    # Catalogamos el estado
    status = info_release.get("status", "")

    if status == "not-affected":
        return True

    if status == "resolved":
        # Capa 0: el parche existe en Debian, comprobamos si el usuario lo tiene instalado
        version_fix = info_release.get("fixed_version", "")
        if version_fix:
            if comparar_versiones_nativa(version_instalada, version_fix):
                # La versión instalada ya incluye el fix → falso positivo
                return True
            else:
                # El parche existe pero el usuario no lo ha instalado → sigue vulnerable
                return False
        else:
            # No hay versión de fix disponible, descartamos por precaución
            return True

    if status in ("open", "undetermined"):
        return False

    return None


##################################################################################################################################################################
################### Dispatcher ###################################################################################################################################
##################################################################################################################################################################

def cve_parcheado(cve_id, nombre_paquete, version_instalada):
    # Simplemente se encarga de mandarle el código a el tracker de Ubuntu o al de Debian, separa todo para hacerlo más fácil de entender
    if TIPO_TRACKER == "ubuntu":
        return cve_parcheado_ubuntu(cve_id, nombre_paquete, version_instalada)
    if TIPO_TRACKER == "debian":
        return cve_parcheado_debian(cve_id, nombre_paquete, version_instalada)
    return None


####################################################################################################################################################################
########### Operaciones OSV.dev ####################################################################################################################################
####################################################################################################################################################################

def comparar_versiones_nativa(v_instalada, v_fixed):
    # Simplemente comparamos la versión de un paquete con la versión arreglada del mismo para comprobar si es anterior o posterior, hacemos aquí el import por si acaso
    try:
        import apt_pkg
        apt_pkg.init_system()
        return apt_pkg.version_compare(v_instalada, v_fixed) >= 0

    except Exception:
        # Es menos optimo que con apt_package pero funciona en todos los sistemas debdian
        res = subprocess.run(
            ['dpkg', '--compare-versions', v_instalada, 'ge', v_fixed],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0


def parse_vector(data):

    # Obtenemos el CVSS del paquete, como OSV tiene varias formas de mandarlo comprobamos todaas ellas

    # Viene directamente la vuln con su CVSS en el campo severity del JSON respuesta
    if "severity" in data:
        for sev in data["severity"]:
            score = sev.get("score")

            # Caso de que venga directamente en formato númerico (1.0, 4.2...)
            if isinstance(score, (int, float)):
                return float(score)

            # Caso de que venga en formato de CVSS, es obligatorio que usemos la librería para obtenerlo
            if isinstance(score, str) and LIBRERIA_CVSS:
                try:
                    if "CVSS:3" in score:
                        return CVSS3(score).scores()[0]
                    if "CVSS:2" in score:
                        return CVSS2(score).scores()[0]
                except Exception:
                    pass

    # El campo severity viene vacío, puede estar en database_specific (no es normal pero puede ser)
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

    # Si finalmente no se encuentra nada, devolvemos None (esto más adelante se interpreta como -1 y en el reporte final se traduce como desconocido)
    return None


def obtener_score_con_cache(vid, v_data, sesion):
    # Tratamos de obtener el resultado en la caché de CVEs para no realizar una petición a OSV.dev (esto nos permite optimizar enormemente el proceso en tiempo)
    with _cache_lock: # Bloqueamos pq accedemos a la caché temporal
        if vid in cache_detalles_osv:
            return cache_detalles_osv[vid]

    # Tratamos de obtener el CVE del propio vector de datos
    score = parse_vector(v_data)

    # Si en este punto no hemos obtenido la info consultamos la API de OSV.dev
    if score is None:
        try:
            r = sesion.get(OSV_VULN_URL.format(vid), timeout=TIMEOUT)
            if r.status_code == 200:

                # Sacamos el CVSS
                score = parse_vector(r.json())
        except Exception:
            pass

    resultado = {"score": score, "data": v_data}

    # Guardamos el resultado en la caché, de forma que si otro paquete tiene el mismo CVE, como en el JSON indexamos con el CVE lo podremos localizar y no será neesario el
    # volver a hacer una petición a la API (lo que explicabamos arriba)
    with _cache_lock:
        cache_detalles_osv[vid] = resultado

    return resultado


def normalizar(valor):
    # Como OSV nos devuelve los CVEs con un formato variable (no siempre empieza igual, ya que cambia mucho en función del entorno)

    # En este caso el CVE viene correctamente y lo devolvemos tal cual
    if valor.startswith("CVE-"):
        return valor

    # En caso de que venga con el entorno delante, quitamos el prefijo
    for prefijo in ("DEBIAN-CVE-", "UBUNTU-CVE-"):
        if valor.startswith(prefijo):
            return valor.replace(prefijo, "CVE-", 1)

    # Ignoramos todo lo que no venga en formato CVE
    return None


def obtener_cves_reales(v):
    # Guardamos el CVE en un set para evitar repetidos (esto se debe a que pueden haber repetidos juntando id y alias)
    cves = set()

    # Cogemos el CVE que nos ha devuelto OSV y lo normalizamos,
    cve = normalizar(v.get("id", ""))
    if cve:
        cves.add(cve)

    # La API muchas veces manda los CVEs en alias
    for alias in v.get("aliases", []):
        cve = normalizar(alias)
        if cve:
            cves.add(cve)
    # Lo devolvemos en formato de lista ya que es mucho más fácil para trabajar y ya sabemos que no tenemos duplicados
    return list(cves)


def es_falso_positivo_so(version_instalada, vuln_data):
    # El JSON que recibimos de OSV contiene el parámetro affected, el cual indica los entornos en los que afecta la vuln así como el paquete([{bash, Debian},{bash, Kali}]) con
    # una lista de diccionarios (realmente una profundidad de 2 diccionarios pero no importa para la explicación)

    # Miramos cada entrada de affected
    for affected in vuln_data.get("affected", []):
        # Miramos las versiones vulnerables
        for r in affected.get("ranges", []):
            # Nos aseguramos que realmente es una versión "correcta" (si no se pone puede explotar pq lleguen cosas raras)
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue

            # Buscamos en el quivalente al control de cambios que da OSV hasta que pillamos la versión que parchea la vuln, después comprobamos si nuestra versión
            # es igual o superior a la del parche
            for event in r.get("events", []):
                if "fixed" in event:
                    if comparar_versiones_nativa(version_instalada, event["fixed"]):
                        return True
    return False


##################################################################################################################################################################
################### Consultas y peticiones #######################################################################################################################
##################################################################################################################################################################

def post_con_reintentos(sesion, url, payload):
    # Vamos a hacer las peticiones con un sistema de backoff, vamos a reenviar las peticiones siempre que no se exceda el max num de intentos
    for intento in range(MAX_REINTENTOS):
        try:
            # realizamos la petición
            r = sesion.post(url, json=payload, timeout=TIMEOUT)

            # Si la API responde correctamente, devolvemos directamente el paquete que hemos recibido
            if r.status_code == 200:
                return r.json()

            # En caso de que haya un fallo DE PARTE DEL CLIENTE, no lo volvemos a intentar, ya que muy probablemente va a volver a fallar (el fallo es nuetro)
            if r.status_code < 500:
                print_c("  [!] OSV devolvió "+str(r.status_code)+", lote descartado")
                return None

        # Si la petición falla, aborta y vuelve a mandar el paquete
        except requests.exceptions.RequestException as e:
            print_c("  [!] Intento "+str(intento + 1)+"/"+str(MAX_REINTENTOS)+" fallido: "+str(e))

        # Si hay un fallo del servidor el hilo espera antes de volver a mandar un apetición para no sobresaturar el servidor (el tiempo de espera es exponencial)
        time.sleep(2 ** intento)
    print_c("   [ERROR] Lote descartado tras agotar reintentos")
    return None


def construir_consultas_apt(paquetes_apt):
    consultas = []
    meta = []

    # Recorremos todos los paquetes del sistema
    for p in paquetes_apt:
        for ecosistema in ECOSISTEMAS_SO:
            # Para los ecosistemas encontrados (pueden ser Debian o Ubuntu y Debian) preparamos un paquete donde guardamos el paquete con su entorno y su versión
            consultas.append({
                "package": {"name": p["name"], "ecosystem": ecosistema},
                "version": p["version"]
            })

            # Por limitaciones de la API, no nos devuelve la respuesta indicando el paquete de envío, por lo que clonamos el diccionario para saber a que petición pertenece que respuesta
            meta.append({**p, "ecosystem": ecosistema})
    return consultas, meta


##################################################################################################################################################################
################### Resultados ###################################################################################################################################
##################################################################################################################################################################

def procesar_resultados_batch(resultados_osv, paquetes_meta, cfg_vulns, sesion):

    # Recolectamos varias variables y preparamos todo
    min_cvss = float(cfg_vulns.get("min_cvss_score", 0.0))
    lista_ignorados = set(cfg_vulns.get("ignorar") or [])
    usar_tracker = TIPO_TRACKER is not None

    # Aquí vamos a acumular los CVEs con sus paquetes
    acumulador = {}

    # Como la API no nos devuelve el paquete al que está contestando pero si contesta en el mismo orden de envío, vamos a usar enumerate, de esta forma con nuestra
    # lista de paquetes meta vamos a obtener el paquete al que hace referencia cada vulnerabilidad, es decir vamos recorriendo meta y res de forma simultanea y mapeando
    # a cada paquete su vulnerabilidad
    for index, res in enumerate(resultados_osv):

        # Si la respuesta no tiene vulnerabilidades pasamos al siguiente paquete de la respuesta
        if "vulns" not in res:
            continue

        pkg = paquetes_meta[index]
        clave = pkg["name"]

        if clave not in acumulador:
            acumulador[clave] = {
                "paquete": pkg["name"],
                "version": pkg["version"],
                "tipo": pkg["type"],
                "cves_vistos": set(),
                "cves": []
            }

        for v in res["vulns"]:
            cves_reales = obtener_cves_reales(v)
            if not cves_reales:
                continue

            vid = v["id"]
            cached = obtener_score_con_cache(vid, v, sesion)
            v_full = cached["data"]
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

                # Capa 2 + Capa 0: Security Tracker con comparación de versión instalada
                if usar_tracker and pkg["type"] == "System (APT)":
                    if cve_parcheado(cve_id, pkg["name"], pkg["version"]) is True:
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


def trabajador_lote(lote_info):
    consultas_lote, meta_lote, cfg_vulns = lote_info
    sesion = requests.Session()
    data   = post_con_reintentos(sesion, OSV_BATCH_URL, {"queries": consultas_lote})
    if not data:
        return []
    return procesar_resultados_batch(data.get("results", []), meta_lote, cfg_vulns, sesion)


def escanear_vulnerabilidades(paquetes_apt):
    cfg_vulns = config.get("vulnerabilities", {})

    consultas_apt, meta_apt = construir_consultas_apt(paquetes_apt)

    lotes = []
    for i in range(0, len(consultas_apt), TAM_LOTE):
        lotes.append((
            consultas_apt[i:i + TAM_LOTE],
            meta_apt[i:i + TAM_LOTE],
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


##################################################################################################################################################################
################### Escaner ######################################################################################################################################
##################################################################################################################################################################

def ESCANER_vulnerabilidades(verbose):
    mostrar_subtitulos("Vulnerabilidades")
    print("")
    print_c("[+] Iniciando módulo de escaneo de vulnerabilidades")

    if not ECOSISTEMAS_SO:
        print_c("   [!] Distribución de Linux no compatible (no es de la familia Debian/Ubuntu). No se puede ejecutar el módulo")
        return {"paquetes": {"apt": 0, "pip": 0}, "vulns": []}

    # Inicializar tracker según distro
    if TIPO_TRACKER == "ubuntu":
        print_c("   [i] Ubuntu Security Tracker activo (codename: "+CODENAME_TRACKER+")")
    elif TIPO_TRACKER == "debian":
        print_c("   [i] Debian Security Tracker activo (codename: "+CODENAME_TRACKER+")")
        cargar_debian_tracker()  # descarga única antes del escaneo
    else:
        print_c("   [!] No hay Security Tracker disponible para esta distribución")

    if not LIBRERIA_CVSS:
        print_c("   [!] Instala cvss en el entorno virtual, ya que la instalación falló: pip install cvss")

    p_apt = mSystem.paquetes_instalados()

    print_c("   [i] Paquetes detectados del sistema (APT): " + str(len(p_apt)))

    resultados = escanear_vulnerabilidades(p_apt)
    print_c("  [i] Se han encontrado " + str(len(resultados)) + " paquetes vulnerables")
    print_c("[-] Finalizando módulo de escaneo de vulnerabilidades")
    return {
        "paquetes": {"apt": len(p_apt)},
        "vulns": resultados
    }