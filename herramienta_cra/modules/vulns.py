import requests
import modules.system as mSystem
import time
import subprocess
import gzip
import os
import datetime
from config.settings import config
from core.colores_terminal import print_c, mostrar_subtitulos

# Importamos la librería para calcular el vector CVSS localmente
try:
    from cvss import CVSS2, CVSS3, CVSS4
    LIBRERIA_CVSS = True
except ImportError:
    LIBRERIA_CVSS = False

# --- CACHÉS Y SESIÓN DE RED GLOBAL PARA MÁXIMA VELOCIDAD ---
cache_cvss = {}              
cache_detalles_osv = {}      
INFO_SO_SISTEMA = None       

# Arma secreta del rendimiento: reutiliza conexiones TCP/TLS
session_http = requests.Session()

def obtener_contexto_so():
    """Obtiene dinámicamente la versión y año de corte."""
    global INFO_SO_SISTEMA
    if INFO_SO_SISTEMA: return INFO_SO_SISTEMA
    
    info_raw = mSystem.info_sis()
    version_str = info_raw.get('version', '0.0') 
    
    try:
        # Extraemos solo los dígitos del primer bloque de la versión
        version_id = "".join(filter(str.isdigit, version_str.split('.')[0]))
        if not version_id: raise ValueError # Si no hay números, forzamos el fallo
        año_lanzamiento = int("20" + version_id)
    except:
        # Si falla el parseo, usamos el año actual (2026 en este contexto)
        año_lanzamiento = datetime.datetime.now().year
        
    INFO_SO_SISTEMA = {
        "version": version_str,
        "dist": info_raw.get('dist', '').lower(),
        "año_corte": año_lanzamiento - 4 
    }
    return INFO_SO_SISTEMA

def cve_esta_en_changelog(paquete, cve_id):
    """Busca el CVE limpio en los registros del disco."""
    rutas = [
        f"/usr/share/doc/{paquete}/changelog.Debian.gz",
        f"/usr/share/doc/{paquete}/changelog.gz"
    ]
    for ruta in rutas:
        if os.path.exists(ruta):
            try:
                with gzip.open(ruta, 'rt', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if cve_id.lower() in line.lower(): return True 
                        if i > 1500: break 
            except: pass
    return False

def es_falso_positivo_so(version_instalada, vuln_data, paquete_nombre):
    """Filtro matriz: Antigüedad, Evidencia y Motores Nativos."""
    ctx = obtener_contexto_so()
    vuln_id = vuln_data.get("id", "")
    
    cve_limpio = vuln_id
    if "CVE-" in vuln_id:
        partes = vuln_id.split("-")
        for idx, parte in enumerate(partes):
            if parte == "CVE":
                cve_limpio = "-".join(partes[idx:])
                break

    try:
        año = int(cve_limpio.split("-")[1])
        if año < ctx["año_corte"]: return True
    except: pass

    if cve_esta_en_changelog(paquete_nombre, cve_limpio): return True

    if "affected" in vuln_data:
        for affected in vuln_data["affected"]:
            for r in affected.get("ranges", []):
                if r.get("type") == "ECOSYSTEM":
                    for event in r.get("events", []):
                        if "fixed" in event:
                            v_fixed = event["fixed"]
                            try:
                                res = subprocess.run(
                                    ['dpkg', '--compare-versions', version_instalada, 'ge', v_fixed],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                                )
                                if res.returncode == 0: return True
                            except: pass
    return False

def obtener_score_cvss(cve_id):
    """Consulta segura al NIST con gestión de rate-limit y sesión persistente."""
    if cve_id in cache_cvss: return cache_cvss[cve_id]
    if not cve_id.startswith("CVE-"): return 0.0
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    api_key = config.get("vulnerabilities", {}).get("nist_api_key")
    headers = {"apiKey": api_key} if api_key else {}
    
    try:
        r = session_http.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            vulnerabilities = r.json().get("vulnerabilities", [])
            if vulnerabilities:
                metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
                for m_type, m_list in metrics.items():
                    if m_list:
                        score = m_list[0].get("cvssData", {}).get("baseScore", 0.0)
                        cache_cvss[cve_id] = score
                        
                        # Respeto estricto al NIST para evitar baneos
                        time.sleep(0.6 if api_key else 6.0) 
                        return score
    except: pass
    return 0.0

def extraer_score_osv_profundo(vuln_id, vuln_data):
    """Petición profunda a OSV optimizada con sesión TCP."""
    def parse_vector(data):
        if "severity" in data and LIBRERIA_CVSS:
            for sev in data["severity"]:
                vector, tipo = sev.get("score", ""), sev.get("type", "")
                try:
                    if "V3" in tipo: return CVSS3(vector).scores()[0]
                    if "V2" in tipo: return CVSS2(vector).scores()[0]
                    if "V4" in tipo: return CVSS4(vector).scores()[0]
                except: pass
        return None

    score = parse_vector(vuln_data)
    if score is not None: return score
        
    try:
        r = session_http.get(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=5)
        if r.status_code == 200:
            full_data = r.json()
            if "affected" in full_data: vuln_data["affected"] = full_data["affected"]
            score = parse_vector(full_data)
            if score: return score
            
            db_spec = full_data.get("database_specific", {})
            if "nvd_cvss3" in db_spec: return float(db_spec["nvd_cvss3"]["cvssV3"]["baseScore"])
    except: pass
    return None

def escanear_vulnerabilidades(paquetes):
    """Motor de escaneo. Combina lotes gigantes, YAML whitelist y cachés."""
    ctx = obtener_contexto_so()
    
    # Extraemos valores del controls.yaml
    cfg_vulns = config.get("vulnerabilities", {})
    min_cvss = float(cfg_vulns.get("min_cvss_score", 0.0))
    lista_ignorados = cfg_vulns.get("ignorar", [])
    
    url = "https://api.osv.dev/v1/querybatch"
    consultas = [{"package": {"name": p['name'], "ecosystem": p['ecosystem']}, "version": p['version']} for p in paquetes]
    hallazgos = []

    # MEGA-LOTES: 200 paquetes de golpe para saturar menos la red
    tam_lote = 200 

    for i in range(0, len(consultas), tam_lote):
        lote = consultas[i:i + tam_lote]
        try:
            response = session_http.post(url, json={"queries": lote}, timeout=15)
            if response.status_code == 200:
                resultados = response.json().get("results", [])
                for index, res in enumerate(resultados):
                    if "vulns" in res:
                        pkg = paquetes[i + index]
                        cves_confirmados = []
                        
                        for v in res['vulns']:
                            vid = v['id']

                            vid_limpio = vid
                            if "CVE-" in vid:
                                partes = vid.split("-")
                                for idx, parte in enumerate(partes):
                                    if parte == "CVE":
                                        vid_limpio = "-".join(partes[idx:])
                                        break

                            # CORTAFUEGOS 1: YAML WHITELIST (Bloqueo instantáneo)
                            if vid in lista_ignorados or vid_limpio in lista_ignorados:
                                continue

                            # CORTAFUEGOS 2: AÑO (Bloqueo sin red)
                            try:
                                año = int(vid_limpio.split("-")[1])
                                if año < ctx["año_corte"]: continue
                            except: pass

                            # DESCARGA OPTIMIZADA CON CACHÉ
                            if vid not in cache_detalles_osv:
                                score = extraer_score_osv_profundo(vid, v)
                                cache_detalles_osv[vid] = {'score': score, 'data': v}
                            
                            v_full = cache_detalles_osv[vid]['data']
                            score = cache_detalles_osv[vid]['score']

                            # FILTRADO FALSOS POSITIVOS DEBIAN
                            if pkg['type'] == 'System (APT)':
                                if es_falso_positivo_so(pkg['version'], v_full, pkg['name']):
                                    continue

                            # FALLBACK NIST SEGURO
                            if score is None: score = obtener_score_cvss(vid_limpio)
                            
                            if score >= min_cvss:
                                cves_confirmados.append({"id": vid, "score": score})

                        if cves_confirmados:
                            hallazgos.append({
                                "paquete": pkg['name'], "version": pkg['version'],
                                "tipo": pkg['type'], "cves": cves_confirmados,
                                "cantidad": len(cves_confirmados)
                            })
        except Exception as e:
            print_c(f"    [ERROR] Fallo en lote OSV: {e}")
            
    return hallazgos

def ESCANER_vulnerabilidades(verbose):
    mostrar_subtitulos("Vulnerabilidades")
    p_apt = mSystem.paquetes_instalados()
    p_pip = mSystem.paquetes_python()
    totales = p_apt + p_pip
    
    print_c(f"     [i] Paquetes Sistema (APT): {len(p_apt)}")
    print_c(f"     [i] Paquetes Python (PIP):  {len(p_pip)}")
    print_c(f"     [i] TOTAL paquetes: {len(totales)}\n")
    
    resultados = escanear_vulnerabilidades(totales)
    print_c(f"\n[+] Análisis completado. Paquetes vulnerables: {len(resultados)}")
    return {"paquetes": {"apt": len(p_apt), "pip": len(p_pip)}, "vulns": resultados}