# SealGuard - Herramienta de Auditoria CRA
# Copyright (C) 2026 Alvaro Sanchez Garijo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
from modules.network import ESCANEO_Networking
from modules.system import ESCANEO_info_Simple
from modules.vulns import ESCANER_vulnerabilidades
from modules.integrity import ESCANEO_integridad, generar_baseline
from modules.users import ESCANER_usuarios
from modules.hardening import ESCANER_hardening
from modules.booting import ESCANER_booting
from modules.availability import ESCANER_disponibilidad
import core.operadorBBDD as opBBDD
from core.report_generator import generar_informe
from datetime import datetime
from core.colores_terminal import print_c, print_input, print_table



def seleccionar(mode, verbose):
    # Comprobamos si la BBDD
    if not opBBDD.comp_BBDD():
        opBBDD.crear_BBDD()
        
    match mode:
        case "scan":
            if opBBDD.obtener_baseline_activo():
                escaneo_normal(verbose)
            else:
                print_c("[ERROR] No existe ningún baseline activo en la BBDD, por favor ejecute un escaneo de tipo baseline")
        
        case "baseline":
            generar_escaneo_baseline()

        case "config-bl":
            tiene_arch = opBBDD.mostrar_tabla("baseline")
            if not tiene_arch:
                print_c("[-] Finalizando la herramienta")
                return
            id_str = print_input("[i] Seleccione el id del nuevo archivo baseline o pulse la tecla 'Q' para salir: ")
            if id_str.lower() != 'q':
                try:
                    id_baseline = int(id_str)
                    opBBDD.seleccionar_baseline(id_baseline)
                except ValueError:
                    print_c("[ERROR] Debes introducir ID válido.")
        
        case "recover":
            tiene_arch = opBBDD.mostrar_tabla("reportes")
            if not tiene_arch:
                print_c("[-] Finalizando la herramienta")
                return
            id_str = print_input("[i] Seleccione el id del reporte que desea generar o pulse la tecla 'Q' para salir: ")
            if id_str.lower() != 'q':
                try:
                    id_reporte = int(id_str)
                    reporte = opBBDD.obtener_elemento(id_reporte, "reportes")
                    if reporte:
                        print_c("[+] Reporte "+str(id_reporte)+" recuperado, generando PDF")
                        generar_informe(reporte["fecha"], reporte["datos"]) 
                    else:
                        # Si devuelve None es porque no existe
                        print_c("[ERROR] No existe ningún reporte con el ID "+str(id_reporte))
                except ValueError:
                    print_c("[ERROR] Introduzca un ID válido")
            
        case "history":
            _ = opBBDD.mostrar_tabla("baseline")
            _ = opBBDD.mostrar_tabla("reportes") 
            
        case "delete":
            opBBDD.borrar_BBDD()     
              
        







def generar_escaneo_baseline():
    archivo = generar_baseline()
    if archivo:
        # Calculamos la fecha 
        fecha_actual = datetime.now().strftime("%Y/%m/%d %H:%M")
        opBBDD.insertar_elemento(archivo, "baseline", fecha_actual)






    
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
        "hardening": {},
        "boot": {},
        "disponibilidad": {}
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
    
    # Obtenemos el resultado de los permisos y dueño de /etc/default/grub
    datos_grub = ''
    for archivos in datos_reporte["hardening"]["archivos_criticos"]:
        if archivos["archivo"] == '/etc/default/grub':
            datos_grub = archivos
    
    datos_reporte["boot"] = ESCANER_booting(verbose, datos_grub)
    datos_reporte["disponibilidad"] = ESCANER_disponibilidad(verbose)
    
    # Obtenemos la fecha
    fecha_actual = datetime.now().strftime("%Y/%m/%d %H:%M")
    opBBDD.insertar_elemento(datos_reporte, "reportes", fecha_actual)
    
    # Generamos el PDF
    print_c("[Ok] Escaneo finalizado correctamente, generando PDF")
    generar_informe(fecha_actual, datos_reporte)