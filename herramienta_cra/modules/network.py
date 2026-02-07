import nmap
import sys
from config.settings import config

def scaneoPuertos(lista_ips, verbose):
    print("[+] Iniciando módulo de networking")
    if verbose:
        print("     [i] Interfaces a escanear: "+str(lista_ips)+"\n")
    
    nm = nmap.PortScanner()
    white_list = config['network']['white_list']
    black_list = config['network']['black_list']
    resultados = []

    # Bucle principal
    for ip in lista_ips:
        if verbose:
            print("\n     ----  Escaneando Interfaz: "+ip+"  ----")

        try:
            nm.scan(ip, arguments='-p- -sV --version-light --max-retries 1 -T4 --open') 
            
        except nmap.PortScannerError:
            print("     [ERROR] No se ha encontrado nmap\n")
            sys.exit(1)
            
        except Exception as e:
            print("     [ERROR] Fallo al ejecutar nmap en "+ip+": "+str(e)+"\n")
            continue 

        # --- CORRECCIÓN AQUÍ ---
        # 1. Comprobamos si nmap no devolvió ningún host (caso común cuando no hay nada abierto)
        if len(nm.all_hosts()) == 0:
            print("     [i] No se ha detectado ningún puerto abierto en la interfaz \n")
            continue # Pasamos a la siguiente IP

        # 2. Variable bandera para saber si encontramos algo dentro de los bucles
        mensajeDetect = False

        for host in nm.all_hosts():
            nombre_host = nm[host].hostname()
            if verbose:
                print("     Nombre del host: "+nombre_host)
            
            for proto in nm[host].all_protocols():
                puertos = nm[host][proto].keys()
                
                for puerto in sorted(puertos): 
                    # Si entramos aquí, es que hay al menos un puerto
                    mensajeDetect = True 
                    
                    info_puerto = nm[host][proto][puerto]
                    servicio = info_puerto['name'].lower()
                    producto = info_puerto['product']
                    version = info_puerto['version']
                    
                    servicio_completo = f"{servicio} {producto} {version}".strip()
                    
                    estado = "UNKNOWN"
                    mensaje = ""
                    peligro = "INFO"

                    # Black list
                    if servicio in black_list:
                        estado = "FAIL"
                        motivo = black_list[servicio]
                        mensaje = "PROHIBIDO: " + motivo
                        peligro = "ALTO"
                        if verbose:
                            print("     [X] "+str(puerto)+"/"+proto+" - "+servicio_completo+" -> "+mensaje)

                    # White list 
                    elif servicio in white_list:
                        estado = "PASS"
                        mensaje = "Servicio autorizado en política."
                        peligro = "BAJO"
                        if verbose:
                            print("     [V] "+str(puerto)+"/"+proto+" - "+servicio_completo+" -> OK")

                    # Desconocido
                    else:
                        estado = "DESCONOCIDO"
                        mensaje = "Servicio no listado ("+servicio+"), revisar política"
                        peligro = "MEDIO"
                        if verbose:
                            print("     [!] "+str(puerto)+"/"+proto+" - "+servicio_completo+" -> "+mensaje)

                    resultados.append({
                        "ip": ip,  
                        "puerto": puerto,
                        "protocolo": proto,
                        "servicio": servicio,
                        "detalle": servicio_completo,
                        "estado": estado,
                        "mensaje": mensaje,
                        "peligro": peligro
                    })
                    
        if not mensajeDetect:
            print("     [i] No se ha detectado ningún puerto abierto en la interfaz \n")

    print("\n[-] Finalizando módulo de networking")
    return resultados