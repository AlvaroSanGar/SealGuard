import requests
import modules.system as mSystem
import json
import time
from config.settings import config
from core.colores_terminal import print_c



# Diccionario caché para no consultar el NIST dos veces por el mismo CVE 
cache_cvss = {}

def obtener_score_cvss(cve_id):
    if cve_id in cache_cvss:
        return cache_cvss[cve_id]
        
    # El NIST solo entiende IDs que empiecen por CVE. Si OSV devuelve un GHSA, le ponemos 0.0
    if not cve_id.startswith("CVE-"):
        cache_cvss[cve_id] = 0.0
        return 0.0
        
    # Extraemos la clave del diccionario de configuración
    api_key = config["vulnerabilities"].get("nist_api_key")
    headers = {"apiKey": api_key} if api_key else {}
        
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        # Añadimos las cabeceras (headers) a la petición GET
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200: 
            datos = response.json()
            vulnerabilidades = datos.get("vulnerabilities", [])
            
            if vulnerabilidades:
                metricas = vulnerabilidades[0].get("cve", {}).get("metrics", {})
                score = 0.0
                if "cvssMetricV31" in metricas:
                    score = metricas["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV3" in metricas:
                    score = metricas["cvssMetricV3"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metricas:
                    score = metricas["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    
                cache_cvss[cve_id] = score
                # Mantenemos la pausa para asegurar estabilidad
                time.sleep(0.5) 
                return score
                
    except Exception:
        pass
        
    cache_cvss[cve_id] = 0.0
    return 0.0





################################################################################################################

def escanear_vulnerabilidades(paquetes):
    print_c("     [i] Consultando base de datos OSV.dev para " + str(len(paquetes)) + " paquetes...")
    
    # Obtenemos el peligro mínimo del yaml
    min_cvss = float(config["vulnerabilities"].get("min_cvss_score", 0.0))
    
    url = "https://api.osv.dev/v1/querybatch"
    consultas = []
    for paquete in paquetes:        
        consultas.append({
            "package": {
                "name": paquete['name'],
                "ecosystem": paquete['ecosystem']
            },
            "version": paquete['version']
        })

    # Mandamos 50 paquetes por tanda para no sobrecargar la API, esto se puede cambiar
    nPeticiones = 50
    hallazgos = []
    for i in range(0, len(consultas), nPeticiones):
        lote = consultas[i:i + nPeticiones] # Cojemos las peticiones entre i y i+n, en el primer caso sería de la 1 a la 50
        
        try:
            response = requests.post(url, json={"queries": lote})
            if response.status_code == 200:
                resultados = response.json().get("results", [])
                
                # Resultados viene en el mismo orden que el lote enviado
                for index, res in enumerate(resultados):
                    if "vulns" in res and res["vulns"]:
                        # Recuperamos el paquete original para tener sus datos
                        pkg_orig = paquetes[i + index]
                        
                        # Extraemos los IDs de los CVEs y calculamos su CVSS
                        cves = []
                        for v in res['vulns']:
                            vuln_id = v['id']
                            score = obtener_score_cvss(vuln_id)
                            
                            # Solo guardamos si el score es mayor o igual al yaml
                            if score >= min_cvss:
                                cves.append({"id": vuln_id, "score": score})
                        
                        # Solo creamos el hallazgo si al menos 1 CVE superó el filtro CVSS
                        if len(cves) > 0:
                            detalle_url = "https://osv.dev/list?q=" + pkg_orig['name']
                            
                            hallazgo = {
                                "paquete": pkg_orig['name'],
                                "version": pkg_orig['version'],
                                "tipo": pkg_orig.get('type', 'Unknown'),
                                "cves": cves,
                                "cantidad": len(cves),
                                "detalle_url": detalle_url
                            }
                            hallazgos.append(hallazgo)
            else:
                print_c("    [!] Error en lote " + str(i) + ": Status " + str(response.status_code))
                
        except Exception as e:
            print_c("    [ERROR] Fallo de conexión con OSV.dev: " + str(e))

    return hallazgos





def ESCANER_vulnerabilidades(verbose):
    # Diccionario de retorno con la estructura solicitada
    datos_reporte = {
        "paquetes": {
            "apt": 0,
            "pip": 0
        },
        "vulns": []
    }

    print("\n--- [ FASE 2: AUDITORÍA DE VULNERABILIDADES ] ---")
    print_c("[+] Iniciando listado de paquetes instalados")
    
    # Obtenemos ambos tipos de paquetes
    paquetes_apt = mSystem.paquetes_instalados()
    paquetes_pip = mSystem.paquetes_python()
    
    # Sumamos las listas
    paquetes_totales = paquetes_apt + paquetes_pip
    
    # Guardamos en datos_reporte el num de paquetes pip y apt
    datos_reporte["paquetes"]["apt"] = len(paquetes_apt)
    datos_reporte["paquetes"]["pip"] = len(paquetes_pip)
    
    print_c("     [i] Paquetes de Sistema (APT): " + str(len(paquetes_apt)))
    print_c("     [i] Paquetes de Python  (PIP): " + str(len(paquetes_pip)))
    print_c("     [i] TOTAL paquetes detectados: " + str(len(paquetes_totales)))
    
    # Ejemplo de top 3 paquetes encontrados
    if (len(paquetes_totales) > 0) and verbose:
        ejemplos = []
        for p in paquetes_totales[:3]:
            ejemplos.append(p['name'] + " " + p['version'])     
        print_c("   [i] Ejemplos: " + ", ".join(ejemplos) + "...")
    elif verbose:
        print_c("    [i] No se detectaron paquetes")

    print_c("[-] Finalizando listado de paquetes")

    ####################################################################################################################
    
    print_c("[+] Iniciando módulo de detección de vulnerabilidades")
    if len(paquetes_totales) > 0:
        # Llamamos al escáner
        vulns = escanear_vulnerabilidades(paquetes_totales)
        datos_reporte["vulns"] = vulns
        
        print_c("[+] Análisis completado.")
        print_c("   [i] Paquetes vulnerables detectados: " + str(len(vulns)))
        
        if verbose and len(vulns) > 0:
            print_c("\n    [TOP 5 HALLAZGOS CRÍTICOS]")
            # Ordenamos para ver los que tienen mas CVEs primero
            vulns.sort(key=lambda x: x['cantidad'], reverse=True)
            
            for v in vulns[:5]:
                primer_cve = v['cves'][0]['id']
                primer_score = v['cves'][0]['score']
                print_c("     [!] [" + v['tipo'] + "] " + v['paquete'] + " v" + v['version'] + " -> " + str(v['cantidad']) + " Vulns (" + primer_cve + " [CVSS: " + str(primer_score) + "]...)")
    else:
        print_c("[!] No hay paquetes para analizar (Fase 2 vacía).")
    print_c("[-] Finalizando módulo de detección de vulnerabilidades")

    return datos_reporte