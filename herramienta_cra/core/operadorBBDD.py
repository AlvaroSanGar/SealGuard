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
import sqlite3
import os
import json  
from core.colores_terminal import print_c, print_table, print_input

DDBB_path = 'history/BBDD-local.db'

############# COMPROBAR SI LA BBDD EXISTE #################################################################
def comp_BBDD():
    print_c("[+] Comprobando si existe una BBDD local")
    try:
        if os.path.exists('history/BBDD-local.db'):
            return True
        else: 
            return False
        
    except Exception as e:
        print_c("[ERROR] No se ha podido detectar la BBDD local: "+str(e))
    return None



############# CREAR BBDD Y TABLAS ##########################################################################
def crear_BBDD():
    # Comprobamos si la BBDD existe, en cuyo caso la borramos
    if os.path.exists(DDBB_path):
        try:
            os.remove(DDBB_path)
            print_c("[i] Base de datos borrada con éxito")

        except PermissionError:
            print_c("[ERROR] Fallo al tratar de borrar la BBDD anterior debido a la falta de permisos adecuados")
        except Exception as e:
            print_c("[ERROR] Fallo al tratar de borrar la BBDD anterior: "+str(e))

    # Creamos la BBDD así como las tablas para los archivos normales y los baseline
    con = sqlite3.connect(DDBB_path)
    # Comenzamos a crear las tablas
    try:
        cursor = con.cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS reportes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha DATE NOT NULL,
                datos_reporte JSON NOT NULL
                
            );
                       
            CREATE TABLE IF NOT EXISTS baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha DATE NOT NULL,
                datos_baseline JSON NOT NULL,
                activo INTEGER NOT NULL DEFAULT 0                         
            );
        ''')

        con.commit()
        print_c("[+] Base de datos creada con éxito")

    except Exception as e:
        print_c("Se ha producido un error durante la creación de la BBDD: "+str(e))

    finally:
        if con:
            con.close()




########### MOSTRAR TABLA ##########################################################################
def mostrar_tabla(tabla):
    # Realizamos las  siguientes comprobaciones previas:
    # Comprobamos si la BBDD existe
    if not os.path.exists(DDBB_path):
        print_c("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
   
    # Comprobamos si la tabla existe
    if not tabla in ["reportes", "baseline"]:
        print_c("[ERROR] La tabla indicada no existe")
        return 
    
    con = None
    try:
        con = sqlite3.connect(DDBB_path)
        cursor = con.cursor()
        
        # Ejecutamos la consulta, incluyendo activo si es la tabla baseline
        if tabla == "baseline":
            cursor.execute("SELECT id, fecha, activo FROM baseline;")
        else:
            cursor.execute("SELECT id, fecha FROM reportes;")
        registros = cursor.fetchall()
        
        # Mostramos los resultados de forma bonita
        if not registros:
            print_c("[i] La tabla '"+str(tabla)+"' existe, pero actualmente está vacía.")
            return False
        else:
            print_table("\n--- [ CONTENIDO DE LA TABLA: "+str(tabla.upper())+" ] ---")
            if tabla == "baseline":
                print_table("  id  |           fecha            | activo ")
                print_table("------+----------------------------+--------")
            else:
                print_table("  id  |           fecha            ")
                print_table("------+----------------------------")
            
            # Rellenamos las filas
            for fila in registros:
                id_registro = str(fila[0])
                fecha = str(fila[1])
                # {:>4} alinea el ID a la derecha ocupando 4 espacios {:<26} alinea la fecha a la izquierda ocupando 26 espacios
                if tabla == "baseline":
                    activo_str = "  [*]  " if fila[2] == 1 else "       "
                    print_table(f" {id_registro:>4} | {fecha:<26} |{activo_str}")
                else:
                    print_table(f" {id_registro:>4} | {fecha:<26}")
            # Info extra del num de registros que hay                
            print_table("("+str(len(registros))+" filas)\n")
            return True

    except sqlite3.Error as e:
        print_c("[ERROR] Fallo al consultar la tabla '"+str(tabla)+"': "+str(e))
        return False
        
    finally:
        if con:
            con.close()

    





########### INSERTAR ELEMENTO ######################################################################
def insertar_elemento(archivo, tipo, fecha_actual):
    # Comprobamos si la BBDD existe
    if not os.path.exists(DDBB_path):
        print_c("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
   
    # Comprobamos si la tabla existe
    if not tipo in ["reportes", "baseline"]:
        print_c("[ERROR] El tipo de archivo no cuadra con los estimados")
        return 
    
    # Comprobamos que el archivo tiene un formato valido (JSON)
    if isinstance(archivo, (dict, list)):
        datos_json = json.dumps(archivo)
    else:
        datos_json = str(archivo)
        
    # Seleccionamos el nombre de la columna en función de la tabla que sea
    if tipo == "reportes":
        columna_datos = "datos_reporte"
    else:
        columna_datos = "datos_baseline"
    
    con = sqlite3.connect(DDBB_path)
    try:
        cursor = con.cursor()
        
        # Usamos execute con parámetros (?, ?) para evitar que las comillas del JSON rompan el SQL
        if tipo == "baseline":
            # Desactivamos el baseline anterior y marcamos el nuevo como activo
            cursor.execute("UPDATE baseline SET activo = 0;")
            query = "INSERT INTO "+str(tipo)+" (fecha, "+str(columna_datos)+", activo) VALUES (?, ?, 1)"
            cursor.execute(query, (fecha_actual, datos_json))
        else:
            query = "INSERT INTO "+str(tipo)+" (fecha, "+str(columna_datos)+") VALUES (?, ?)"
            cursor.execute(query, (fecha_actual, datos_json))
        
        con.commit()
        print_c("[i] Datos insertados con éxito en la tabla '"+str(tipo)+"'")
        
    except Exception as e:
        print_c("[ERROR] Se ha producido un error durante la inserción en la BBDD: "+str(e))

    finally:
        if con:
            con.close()






########### BORRAR BBDD ############################################################################
def borrar_BBDD():
    # Comprobamos si la BBDD existe
    if not os.path.exists(DDBB_path):
        print_c("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
    
    conf = print_input("¿Seguro que deseas borrar la BBDD? Escribe 'borrar' para confirmar: ")
    if str(conf.lower()) == "borrar":
        try:
            os.remove(DDBB_path)
            print_c("[i] Base de datos borrada con éxito")

        except PermissionError:
            print_c("[ERROR] Fallo al tratar de borrar la BBDD anterior debido a la falta de permisos adecuados")
        except Exception as e:
            print_c("[ERROR] Fallo al tratar de borrar la BBDD anterior: "+str(e))
            
    else:
        print_c("[i] No se ha confirmado la operación")





########## EXTRAER ELEMENTO ########################################################################
def obtener_elemento(id_obj, tabla):
    # Comprobamos si la BBDD o la tabla son válidas (salimos silenciosamente si no)
    if not os.path.exists(DDBB_path):
        print_c("[ERROR] La BBDD no existe") 
        return None

    if tabla not in ["reportes", "baseline"]:   
        print_c("[ERROR] La tabla indicada no existe")
        return None
    
    # Seleccionamos el nombre de la columna
    if tabla == "reportes":
        columna_datos = "datos_reporte"
    else:
        columna_datos = "datos_baseline"
    
    con = None
    try:
        con = sqlite3.connect(DDBB_path)
        cursor = con.cursor()
        query = "SELECT fecha, "+str(columna_datos)+" FROM "+str(tabla)+" WHERE id = ?;"
        cursor.execute(query, (id_obj,))
        registro = cursor.fetchone()
        
        # Si no encontramos nada terminamos
        if not registro:
            return None

        # Obtenemos los datos del reporte para pasarlos a un diccionario
        datos_raw = registro[1]
        
        try:
            # Parseamos el JSON
            diccionario_datos = json.loads(datos_raw)
        except Exception as e:
            # No hacemos nada 
            print_c("[ERROR] No se han podido obtener los datos del archivo JSON: "+str(e))
            diccionario_datos = datos_raw

        # Devolvemos una estructura limpia y estandarizada para el generador de PDFs
        return {
            "fecha": str(registro[0]),
            "datos": diccionario_datos
        }

    except sqlite3.Error as e:
        print_c("[ERROR] "+str(e))
        return None
        
    finally:
        if con:
            con.close()


######### SELECCIONAR BASELINE ################################################
def seleccionar_baseline(id):
    print_c("[+] Asignando el nuevo archivo baseline (id "+str(id)+")")
    archivo = obtener_elemento(id, "baseline")
    if archivo:
        con = None
        try:
            con = sqlite3.connect(DDBB_path)
            cursor = con.cursor()
            cursor.execute("UPDATE baseline SET activo = 0;")
            cursor.execute("UPDATE baseline SET activo = 1 WHERE id = ?;", (id,))
            con.commit()
            print_c("[-] El archivo baseline se ha asignado con exito\n")
            return 
    
        except Exception as e:
            print_c("[ERROR] No se ha podido asignar el archivo baseline: "+str(e))
            return
        finally:
            if con:
                con.close()
    print_c("[ERROR] No se ha podido obtener el archivo baseline indicado")


######### OBTENER BASELINE ACTIVO ################################################
def obtener_baseline_activo():
    if not os.path.exists(DDBB_path):
        return None
    
    con = None
    try:
        con = sqlite3.connect(DDBB_path)
        cursor = con.cursor()
        cursor.execute("SELECT datos_baseline FROM baseline WHERE activo = 1 ORDER BY id DESC LIMIT 1;")
        registro = cursor.fetchone()
        
        if not registro:
            return None
        
        try:
            return json.loads(registro[0])
        except Exception as e:
            print_c("[ERROR] No se han podido obtener los datos del baseline activo: "+str(e))
            return None

    except sqlite3.Error as e:
        print_c("[ERROR] "+str(e))
        return None
        
    finally:
        if con:
            con.close()