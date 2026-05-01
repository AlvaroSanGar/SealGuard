from core.auditor import seleccionar
from core.colores_terminal import mostrar_banner

if __name__ == "__main__":
    mostrar_banner()  
    
    mode = "reset"
    verbose = True
    seleccionar(mode, verbose)

    
    # (Comentados temporalmente hasta que se haga el reporte final)
    '''
    print("RESULTADOS SISTEMA\n", datos_reporte["sistema"])
    print("\n\nRESULTADOS DE NETWORKING\n", datos_reporte["puertos"])
    print("\n\nRESULTADOS DE VULNERABILIDADES\n", datos_reporte["vulns"])
    print("\n\nRESULTADOS INTEGRIDAD\n", datos_reporte["integridad"])
    print("\n\nRESULTADOS POLITICAS\n",datos_reporte["politicas_contra"])
    print("\n\nRESULTADOS USUARIOS\n",datos_reporte["usuarios"])
    print("\n\nRESULTADOS 2FA\n",datos_reporte["2FA"])
    '''