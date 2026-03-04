import requests
import modules.system as mSystem
import json

def escanear_vulnerabilidades(paquetes):
    print("     [i] Consultando base de datos OSV.dev para " + str(len(paquetes)) + " paquetes...")
    
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
                        
                        # Extraemos los IDs de los CVEs
                        cves = []
                        for v in res['vulns']:
                            cves.append(v['id'])
                        
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
                print("    [!] Error en lote " + str(i) + ": Status " + str(response.status_code))
                
        except Exception as e:
            print("    [ERROR] Fallo de conexión con OSV.dev: " + str(e))

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
    print("[+] Iniciando listado de paquetes instalados")
    
    # Obtenemos ambos tipos de paquetes
    paquetes_apt = mSystem.paquetes_instalados()
    paquetes_pip = mSystem.paquetes_python()
    
    # Sumamos las listas
    paquetes_totales = paquetes_apt + paquetes_pip
    
    # Guardamos en datos_reporte el num de paquetes pip y apt
    datos_reporte["paquetes"]["apt"] = len(paquetes_apt)
    datos_reporte["paquetes"]["pip"] = len(paquetes_pip)
    
    print("     [i] Paquetes de Sistema (APT): " + str(len(paquetes_apt)))
    print("     [i] Paquetes de Python  (PIP): " + str(len(paquetes_pip)))
    print("     [i] TOTAL paquetes detectados: " + str(len(paquetes_totales)))
    
    # Ejemplo de top 3 paquetes encontrados
    if (len(paquetes_totales) > 0) and verbose:
        ejemplos = []
        for p in paquetes_totales[:3]:
            ejemplos.append(p['name'] + " " + p['version'])     
        print("   [i] Ejemplos: " + ", ".join(ejemplos) + "...")
    elif verbose:
        print("    [i] No se detectaron paquetes")

    print("[-] Finalizando listado de paquetes")

    ####################################################################################################################
    
    print("[+] Iniciando módulo de detección de vulnerabilidades")
    if len(paquetes_totales) > 0:
        # Llamamos al escáner
        vulns = escanear_vulnerabilidades(paquetes_totales)
        datos_reporte["vulns"] = vulns
        
        print("[+] Análisis completado.")
        print("   [i] Paquetes vulnerables detectados: " + str(len(vulns)))
        
        if verbose and len(vulns) > 0:
            print("\n    [TOP 5 HALLAZGOS CRÍTICOS]")
            # Ordenamos para ver los que tienen mas CVEs primero
            vulns.sort(key=lambda x: x['cantidad'], reverse=True)
            
            for v in vulns[:5]:
                primer_cve = v['cves'][0]
                print("     [!] [" + v['tipo'] + "] " + v['paquete'] + " v" + v['version'] + " -> " + str(v['cantidad']) + " Vulns (" + primer_cve + "...)")
    else:
        print("[!] No hay paquetes para analizar (Fase 2 vacía).")
    print("[-] Finalizando módulo de detección de vulnerabilidades")

    return datos_reporte