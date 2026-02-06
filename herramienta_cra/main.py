import modules.network as mNetwork
import modules.system as mSystem

if __name__ == "__main__":
    print("--- [ FASE 1: AUDITORÍA DE PUERTOS ] ---")
    verbose = True
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
    resultadosNetwork = mNetwork.scaneoPuertos(lista_objetivos, verbose)
    
    print("\n\n--- [ FIN DEL ESCANEO ] ---\n")
    print("Total de datos guardados: "+str(len(resultadosNetwork))+"\n")
    print (resultadosNetwork)