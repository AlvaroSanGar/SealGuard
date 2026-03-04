import modules.network as mNetwork
import modules.system as mSystem
import modules.vulns as mVuln 
import modules.integrity as mIntegrity
import modules.users as mUsers

if __name__ == "__main__":
    print("\n==================================================")
    print("      AUDITORÍA DE CUMPLIMIENTO CRA (LINUX)      ")
    print("==================================================\n")
    
    datos_reporte = {
        "sistema": {},  
        "paquetes": [], 
        "vulns": [], 
        "puertos": [],
        "politicas_contra": [],
        "usuarios": [],
        "2FA": []
    }
    verbose = True
    ####################################################################################################################
    '''
    # Info del sistema
    info_sis = mSystem.info_sis() # Es un diccionario
    datos_reporte["sistema"] = info_sis 
    if verbose:
        print("[+] Información del sistema: ")
        print("     [i] Hostname:      "+info_sis['hostname'])
        print("     [i] Sistema:       "+info_sis['dist']+" "+info_sis['version'])
        print("     [i] Kernel:        "+info_sis['kernel'])
        print("     [i] Arquitectura:  "+info_sis['arquitectura']+"\n")
    
    
    ####################################################################################################################
    
    print("--- [ FASE 1: AUDITORÍA DE PUERTOS ] ---")
    interfaces = mSystem.obtener_interfaces() # Diccionario donde cada clave tiene asociada una lista de diccionarios
    lista_objetivos = []
    
    # Usamos las IPv4 para el módulo de networking
    for _, direcciones in interfaces.items():
        for direccion in direcciones:
            if direccion['tipo'] == 'inet':
                lista_objetivos.append(direccion['ip'])

    if lista_objetivos:
        datos_reporte["puertos"] = mNetwork.scaneoPuertos(lista_objetivos, verbose)
    else:
        print("[ERROR] No se detectaron IPs para escanear\n")
    
    
    ####################################################################################################################
    
    print("\n--- [ FASE 2: INVENTARIO DEL SISTEMA ] ---")
    print("[+] Iniciando listado de paquetes instalados")
    
    # Obtenemos ambos tipos de paquetes
    paquetes_apt = mSystem.paquetes_instalados()
    paquetes_pip = mSystem.paquetes_python()
    
    # Sumamos las listas
    paquetes_totales = paquetes_apt + paquetes_pip
    datos_reporte["paquetes"] = paquetes_totales
    
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
        vulns = mVuln.escanear_vulnerabilidades(paquetes_totales)
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

    ####################################################################################################################
    print("\n--- [ FASE 3: INTEGRIDAD DE ARCHIVOS ] ---")
    modo_baseline = False
    
    if modo_baseline:
        mIntegrity.generar_baseline()
    else:
        datos_reporte["integridad"] = mIntegrity.verificar_integridad(verbose)'''
        
   ####################################################################################################################
    usu = mUsers.ESCANER_usuarios(verbose)
    datos_reporte["politicas_contra"] = usu.get("politicas")
    datos_reporte["usuarios"] = usu.get("usuarios")
    datos_reporte["2FA"] = usu.get("2FA")
    ####################################################################################################################

    print("\n\n--- [ FIN DEL ESCANEO ] ---\n")
    
    # (Comentados temporalmente hasta que se haga el reporte final)
    '''
    print("RESULTADOS SISTEMA\n", datos_reporte["sistema"])
    print("\n\nRESULTADOS DE NETWORKING\n", datos_reporte["puertos"])
    print("\n\nRESULTADOS DE VULNERABILIDADES\n", datos_reporte["vulns"])
    print("\n\nRESULTADOS INTEGRIDAD\n", datos_reporte["integridad"])
    '''
    print("\n\nRESULTADOS POLITICAS\n",datos_reporte["politicas_contra"])
    print("\n\nRESULTADOS USUARIOS\n",datos_reporte["usuarios"])
    print("\n\nRESULTADOS 2FA\n",datos_reporte["2FA"])
    