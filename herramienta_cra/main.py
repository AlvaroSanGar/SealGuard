import modules.network as mNetwork
import modules.system as mSystem

if __name__ == "__main__":
    print("\n==================================================")
    print("      AUDITORÍA DE CUMPLIMIENTO CRA (LINUX)      ")
    print("==================================================\n")
    
    datos_reporte = {
        "sistema": {},
        "paquetes": [],
        "puertos": []
    }
    verbose = True
    
    # 1. Info del Host
    info_sis = mSystem.info_sis()
    datos_reporte["sistema"] = info_sis 
    if verbose:
        print("[+] Información del sistema: ")
        print("     [i] Hostname:      "+info_sis['hostname'])
        print("     [i] Sistema:       "+info_sis['distro']+" "+info_sis['version'])
        print("     [i] Kernel:        "+info_sis['kernel'])
        print("     [i] Arquitectura:  "+info_sis['arquitectura']+"\n")
    
    
    print("--- [ FASE 1: AUDITORÍA DE PUERTOS ] ---")
    interfaces = mSystem.obtener_interfaces_red()
    lista_objetivos = []
    
    # Usamos las IPv4 para el módulo de networking
    for nombreIn, direcciones in interfaces.items():
        for direccion in direcciones:
            if direccion['tipo'] == 'inet':
                ip = direccion['ip']
                lista_objetivos.append(ip)

    if not lista_objetivos:
        print("[ERROR] No se detectaron IPs para escanear\n")
        exit(1)
    datos_reporte["puertos"] = mNetwork.scaneoPuertos(lista_objetivos, verbose)
    
    
    
    print("\n--- [ FASE 2: INVENTARIO DEL SISTEMA ] ---")
    print("[+] Iniciadno módulo de revisión de paquetes instalados")
    paquetes = mSystem.paquetes_instalados()
    datos_reporte["paquetes"] = paquetes # Guardamos para el PDF
    
    print("   [i] Total de paquetes detectados: "+str(len(paquetes)))
    
    # Ejemplo para verbose
    if (len(paquetes) > 0) and verbose:
        ejemplos = [f"{p['name']} v{p['version']}" for p in paquetes[:3]]
        print(f"   [i] Ejemplos: {', '.join(ejemplos)}...")
    elif verbose:
        print("    [!] No se detectaron paquetes")

    print("\n\n--- [ FIN DEL ESCANEO ] ---\n")
    print("RESULTADOS SISTEMA\n")
    print(datos_reporte["sistema"])
    print("\n\n\nRESULTADOS DE NETWORKING\n")
    print(datos_reporte["puertos"])
    print("\n\n\nRESULTADOS DE PAQUETES\n")
    #print(datos_reporte["paquetes"])
    
    
    