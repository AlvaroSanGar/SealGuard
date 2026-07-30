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
import hashlib
import json
import os
from config.settings import config
from core.colores_terminal import print_c, mostrar_subtitulos
import core.operadorBBDD as opBBDD


def calcular_integridad(ruta):
    # Comprobamos si existe
    
    if not os.path.exists(ruta):
        return None
    
    try:
        mtime = os.stat(ruta).st_mtime
        ctime = os.stat(ruta).st_ctime
        
        h = hashlib.new("SHA256")
        with open(ruta, "rb") as f: # Abrimos el archivo (se cierra al terminar incluso en fallo) y leemos el binario
            
            # Vamos a leer el archivo hasheado, para ello debemos limitar cuanto va a leer ya que si es muy grande el proceso
            # morirá, para ello usamos una función anonima que leera en bloques de 4096 bytes y parará cuando encuentre bytes 
            # vacios (esto lo hacemos con b"")
            for bloque in iter(lambda: f.read(4096), b""):
                h.update(bloque)
        return {
            "hash": h.hexdigest(),
            "mtime": mtime,
            "ctime": ctime
        }
    
    except PermissionError:
        return "FALTAN PERMISOS"
    
    except Exception as e:
        return "ERROR: "+str(e)




def generar_baseline():
    print("")
    print_c("[+] Iniciando recopilación de hashes críticos")
    # Cargamos los archivos de settings
    try:
        rutas_a_auditar = config["integrity"]
    except KeyError as e:
        rutas_a_auditar = []
    baseline = {}
    
    # Para cada archivo nos guardamos el hash asociado y lo metemos en un diccionario
    for ruta in rutas_a_auditar:
        hash_val = calcular_integridad(ruta)
        # Comprobamos que nos devuelve la función, solo lo guardamos si obtenemos exitosamente el hash
        if hash_val == None:
            print_c("     [!] El archivo '"+ruta+"' no existe")
        
        # Comprobamos si el contenido de hash_val es un string, si es así entonces de trata de un error (por si acaso lo comprobamos también)    
        elif isinstance(hash_val, str) and (hash_val == "FALTAN PERMISOS" or hash_val.startswith("ERROR:")):
            print_c("     [!] No se ha logrado obtener el archivo de '"+ruta+"' -> "+str(hash_val))
            
        else:
            baseline[ruta] = hash_val
            print_c("     [i] Hash del archivo '"+ruta+"' añadido con exito")

    # Lo devolvemos para que el auditor lo almacene en la BBDD
    try:
        print("")
        print_c("[-] El archivo baseline se ha generado con éxito\n")
        return baseline
    
    except Exception as e:
        print_c("[ERROR] No se ha podido generar el archivo baseline: "+str(e))

    




def verificar_integridad(verbose):
    # Comprobamos que se ha realizado un escaneo baseline anteriormente
    guardados = opBBDD.obtener_baseline_activo()
    if not guardados:
        print_c("[!] No se puede realizar el escaneo de integridad ya que no existe ningún baseline activo en la BBDD")
        return None
    print("")
    print_c("[+] Iniciando módulo de integridad")
    
    # Cargamos los archivos de settings
    try:
        rutas_a_auditar = config["integrity"]
    except KeyError as e:
        rutas_a_auditar = []
    
    comp = {}
    
    # Obtenemos los hashes igual que en baseline
    for ruta in rutas_a_auditar:
        hash_val = calcular_integridad(ruta)
        
        # Comprobamos que nos devuelve la función, solo lo guardamos si obtenemos exitosamente el hash
        if hash_val == None:
            print_c("     [!] El archivo '"+ruta+"' no existe")
            
        # Igual que en baseline    
        elif isinstance(hash_val, str) and (hash_val == "FALTAN PERMISOS" or hash_val.startswith("ERROR:")):
            print_c("     [!] No se ha logrado obtener el archivo de '"+ruta+"' -> "+str(hash_val))
            
        else:
            comp[ruta] = hash_val
            if verbose:
                print_c("     [i] Se ha logrado obtener el hash del archivo '"+ruta+"'")
                
    resultados = []
    
    # Comparamos los resultados obtenidos con los guardados
    print("")
    print_c("[+] Comenzado la comparación entre resultados obtenidos y los almacenados")
    for archi, resul in guardados.items():
        detalles_cambio = []
        if archi not in comp:
            estado = "INACCESIBLE / BORRADO"
            if verbose:
                print_c("     [X] " + archi + " -> " + estado)
            
        elif resul == comp[archi]:
            estado = "INTACTO"
            if verbose:
                print_c("     [Ok] " + archi + " -> " + estado)
        
        else:
            estado = "MODIFICADO"
            # Conseguimos el parametro/os que ha cambiado
            if resul.get("hash") != comp[archi].get("hash"):
                detalles_cambio.append("hash")
            
            if resul.get("mtime") != comp[archi].get("mtime"):
                detalles_cambio.append("mtime")
            
            if resul.get("ctime") != comp[archi].get("ctime"):
                detalles_cambio.append("ctime")
                
            if verbose:
                print_c("     [X] " + archi + " -> " + estado + " (Cambios en: " + ", ".join(detalles_cambio) + ")")
            
        resultados.append({
            "archivo": archi,
            "estado": estado,
            "detalles_cambio": detalles_cambio
        })
        
    # Comprobamos si todos los archivos obtenidos están en el listado guardado
    for ruta_actual in comp:
        if ruta_actual not in guardados:
            resultados.append({
                "archivo": ruta_actual,
                "estado": "NO_RASTREADO",
                "detalles_cambio": []
            })
            if verbose:
                print_c("     [!] El archivo '"+ruta_actual+"' no está en el listado del escaneo baseline")
    
    print("")
    print_c("[-] Finalizando módulo de integridad")
    return resultados




def ESCANEO_integridad(verbose):
    mostrar_subtitulos("Integridad")
    resultado = verificar_integridad(verbose)
    return resultado