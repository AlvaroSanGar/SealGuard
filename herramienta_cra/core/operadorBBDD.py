import sqlite3
import os

DDBB_path = 'history/BBDD-local.db'

############# COMPROBAR SI LA BBDD EXISTE #################################################################
def comp_BBDD():
    print("[+] Comprobando si existe una BBDD local")
    try:
        if os.path.exists('history/BBDD-local.db'):
            return 1
        else: 
            return 0
        
    except Exception as e:
        print("[ERROR] No se ha podido detectar la BBDD local: "+str(e))
    return None



############# CREAR BBDD Y TABLAS ##########################################################################
def crear_BBDD():
    # Comprobamos si la BBDD existe, en cuyo caso la borramos
    if os.path.exists(DDBB_path):
        try:
            os.remove(DDBB_path)
            print("[i] Base de datos borrada con éxito")

        except PermissionError:
            print("[ERROR] Fallo al tratar de borrar la BBDD anterior debido a la falta de permisos adecuados")
        except Exception as e:
            print("[ERROR] Fallo al tratar de borrar la BBDD anterior: "+str(e))

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
                datos_baseline JSON NOT NULL                         
            );
        ''')

        con.commit()
        print("[+] Base de datos creada con éxito")

    except Exception as e:
        print("Se ha producido un error durante la creación de la BBDD: "+str(e))

    finally:
        if con:
            con.close()


########### MOSTRAR TABLA ##########################################################################
def mostrar_tabla(tabla):
    # Realizamos las  siguientes comprobaciones previas:
    # Comprobamos si la tabla existe

    
    # Comprobamos si la BBDD existe
    if not os.path.exists(DDBB_path):
        print("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
   
    if not tabla in ["reportes", "baseline"]:
        print("[ERROR] La tabla indicada no existe")
    
    con = None
    try:
        con = sqlite3.connect(DDBB_path)
        cursor = con.cursor()
        
        # Ejecutamos la consulta. 
        cursor.execute("SELECT id, fecha FROM "+str(tabla)+";")
        registros = cursor.fetchall()
        
        # Mostramos los resultados
        if not registros:
            print("[i] La tabla '"+str(tabla)+"' existe, pero actualmente está vacía.")
        else:
            print(f"\n--- [ CONTENIDO DE LA TABLA: {tabla.upper()} ] ---")
            for fila in registros:
                id_registro = fila[0]
                fecha = fila[1]
                print("[*] ID: "+str(id_registro)+" | Fecha: "+str(fecha))

    except sqlite3.Error as e:
        print("[ERROR] Fallo al consultar la tabla '"+str(tabla)+"': "+str(e))
        
    finally:
        if con:
            con.close()

    



########### INSERTAR ELEMENTO ######################################################################

def insertar_elemento(archivo, tipo):


########### BORRAR BBDD ############################################################################



########## EXTRAER ELEMENTO ########################################################################



########## BORRAR ELEMENTO #########################################################################