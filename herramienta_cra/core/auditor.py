from modules.network import ESCANEO_Networking
from modules.system import ESCANEO_info_Simple
from modules.vulns import ESCANER_vulnerabilidades
from modules.integrity import ESCANEO_integridad, generar_baseline
from modules.users import ESCANER_usuarios
from modules.hardening import ESCANER_hardening

def escaneo_baseline():
    generar_baseline()
    
def escaneo_normal(verbose):
    
    datos_reporte = {
        "sistema": {},  
        "paquetes": {}, 
        "vulns": [], 
        "puertos": [],
        "politicas_contra": [],
        "usuarios": [],
        "2FA": [],
        "integridad": [],
        "hardening": {}
    }
    
    datos_reporte["sistema"] = ESCANEO_info_Simple(verbose)
    datos_reporte["puertos"] = ESCANEO_Networking(verbose)
    
    vuln = ESCANER_vulnerabilidades(verbose)
    datos_reporte["paquetes"] = vuln.get("paquetes")
    datos_reporte["vulns"] = vuln.get("vulns")
    
    datos_reporte["integridad"] = ESCANEO_integridad(verbose)
    
    usu = ESCANER_usuarios(verbose)
    datos_reporte["politicas_contra"] = usu.get("politicas")
    datos_reporte["usuarios"] = usu.get("usuarios")
    datos_reporte["2FA"] = usu.get("2FA")
   
    datos_reporte["hardening"] = ESCANER_hardening(verbose)
    