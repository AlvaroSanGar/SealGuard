import requests
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