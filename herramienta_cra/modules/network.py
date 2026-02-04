import nmap
import sys
from config.settings import config

def scaneoPuertos(ip, verbose):
    print("[+] Iniciando módulo de networking\n")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sV -T4 --open')
    
    except nmap.PortScannerError:
        print("[ERROR] No se encuentra ha encontrado nmap\n")
        sys.exit(1)
        
    except Exception as e:
        print("[ERROR] Fallo al ejecutar nmap: "+e+"\n")
        sys.exit(1)
        
    white_list = config['network']['white_list']
    black_list = config['network']['black_list']
    resultados = []
    
    for host in nm.all_hosts():
        nombre_host = nm[host].hostname()
        print(f"\nResultados para: {host} ({nombre_host})")
        
        for proto in nm[host].all_protocols():
            puertos = nm[host][proto].keys()
            
            for puerto in sorted(puertos): 
                info_puerto = nm[host][proto][puerto]
                servicio = info_puerto['name']
                producto = info_puerto['product']
                version = info_puerto['version']
                servicio_completo = f"{servicio} {producto} {version}".strip()
                
                # --- LÓGICA DE CUMPLIMIENTO CRA ---
                estado = "UNKNOWN"
                mensaje = ""
                peligro = "INFO"

                # Black list
                if puerto in black_list:
                    estado = "FAIL"
                    motivo = black_list[puerto]
                    mensaje = "PROHIBIDO: " + motivo
                    peligro = "ALTO"
                    if verbose:
                        print("  [X] " + str(puerto) + "/" + proto+" - "+servicio_completo+" -> "+mensaje+"\n")

                # White list
                elif puerto in white_list:
                    estado = "PASS"
                    mensaje = "Servicio autorizado en política."
                    peligro = "BAJO"
                    if verbose:
                        print("  [V] "+str(puerto)+"/"+proto+" - "+servicio_completo+" -> OK\n")

                # No aparece en la lista
                else:
                    estado = "DESCONOCIDO"
                    mensaje = "El puerto no aparece en ninguna de las listas, preferiblemente no debe estar abierto"
                    peligro = "MEDIO"
                    if verbose:
                        print("  [!] "+str(puerto)+"/"+proto+" - "+servicio_completo+" -> "+mensaje+"\n")

                resultados.append({
                    "id": "RED-PUERTO",
                    "puerto": puerto,
                    "protocolo": proto,
                    "servicio": servicio_completo,
                    "estado": estado,
                    "mensaje": mensaje,
                    "peligro": peligro
                })

    if resultados == []:
        print("  [i] No se encontraron puertos abiertos\n")
    print("[-] Finalizando módulo de networking")
    return resultados