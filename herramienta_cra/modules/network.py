import nmap
import modules.system as mSystem
from config.settings import config
from core.colores_terminal import print_c, mostrar_subtitulos

def escaneo_puertos(lista_ips, verbose):
    print("")
    print_c("[+] Iniciando módulo de networking")
    if verbose:
        print_c("     [i] Interfaces a escanear: "+str(lista_ips)+"\n")
    
    nm = nmap.PortScanner()
    white_list = config['network']['white_list']
    black_list = config['network']['black_list']
    resultados = []

    # Bucle principal
    for ip in lista_ips:
        if verbose:
            print("")
            print_c("---- [ Escaneando Interfaz: "+ip+" ] ----")

        try:
            nm.scan(ip, arguments='-p- -sV --version-light --max-retries 1 -T4 --open') 
            
        except nmap.PortScannerError:
            print_c("     [ERROR] No se ha encontrado nmap (saltando fase de escaneo de puertos)\n")
            return [] # No vamos a poder hacer nada dentro del módulo
            
        except Exception as e:
            print_c("     [ERROR] Fallo al ejecutar nmap en "+ip+": "+str(e)+"\n")
            continue 


        if len(nm.all_hosts()) == 0:
            print_c("     [i] No se ha detectado ningún puerto abierto en la interfaz \n")
            resultados.append({
                "ip": ip,  
                "puerto": "-",
                "protocolo": "-",
                "servicio": "-",
                "detalle": "-",
                "estado": "ACEPTADO",
                "mensaje": "-",
                "peligro": "BAJO"
            })
            continue # Pasamos a la siguiente iteración

        mensaje_p_encontrados = False
        for host in nm.all_hosts():
            nombre_host = nm[host].hostname()
            if verbose:
                print_c("     [i] Nombre del host: "+nombre_host)
            
            for proto in nm[host].all_protocols(): # Con protocolo se refiere a TCP o UDP
                puertos = nm[host][proto].keys()
                
                for puerto in sorted(puertos):  # Los devolvemos ordenados para que sea más cómodo
                    mensaje_p_encontrados = True 
                    info_puerto = nm[host][proto][puerto]
                    servicio = info_puerto['name'].lower()  # En el yaml están en minuscula
                    producto = info_puerto['product']
                    version = info_puerto['version']
                    estado = "UNKNOWN"
                    mensaje = ""
                    peligro = ""
                    
                    # Es más seguro para unirlo todo
                    partes = [str(servicio), str(producto), str(version)]
                    servicio_completo = " ".join(filter(None, partes))
                    
                    # Black list
                    if servicio in black_list:
                        estado = "PROHIBIDO"
                        motivo = black_list[servicio]
                        mensaje = "PROHIBIDO: " + motivo
                        peligro = "ALTO"
                        if verbose:
                            print_c("     [X] "+str(puerto)+"/"+proto+" - "+servicio_completo+" -> "+mensaje)

                    # White list 
                    elif servicio in white_list:
                        estado = "ACEPTADO"
                        mensaje = "Servicio autorizado en política."
                        peligro = "BAJO"
                        if verbose:
                            print_c("     [Ok] "+str(puerto)+"/"+proto+" - "+servicio_completo+" -> OK")

                    # Desconocido
                    else:
                        estado = "DESCONOCIDO"
                        mensaje = "Servicio no listado ("+servicio+"), revisar política"
                        peligro = "MEDIO"
                        if verbose:
                            print_c("     [!] "+str(puerto)+"/"+proto+" - "+servicio_completo+" -> "+mensaje)

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
                    
        if not mensaje_p_encontrados:
            resultados.append({
                "ip": ip,  
                "puerto": "-",
                "protocolo": "-",
                "servicio": "-",
                "detalle": "-",
                "estado": "ACEPTADO",
                "mensaje": "-",
                "peligro": "BAJO"
            })
            print_c("     [i] No se ha detectado ningún puerto abierto en la interfaz \n")

    print("")
    print_c("[-] Finalizando módulo de networking")
    return resultados


def ESCANEO_Networking(verbose):
    mostrar_subtitulos("Networking")
    resultados = []
    interfaces = mSystem.obtener_interfaces() # Diccionario donde cada clave tiene asociada una lista de diccionarios
    lista_objetivos = []
    
    # Usamos las IPv4 para aplicarles nmap y obtener las interfaces levantadas
    for _, direcciones in interfaces.items():
        for direccion in direcciones:
            if direccion['tipo'] == 'inet':
                lista_objetivos.append(direccion['ip'])

    if lista_objetivos:
        resultados = escaneo_puertos(lista_objetivos, verbose)
    else:
        print_c("[ERROR] No se detectaron IPs para escanear\n")
    
    return resultados