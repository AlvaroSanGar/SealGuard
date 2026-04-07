import sqlite3
import os


def comp_BBDD():
    print("[+] Comprobando si existe una BBDD local")
    try:
        if os.path.exists('history/BBDD-local.db'):
            return 1
        else: 
            return 0
        
    except Exception as e:
        print(f"[ERROR] No se ha podido detectar la BBDD local: {e}")
    return None


def crear_BBDD():
    # Comprobamos si la BBDD existe, en cuyo caso la borramos
    if os.path.exists('history/BBDD-local.db'):
        try:
            os.remove('history/BBDD-local.db')
            print("[i] Base de datos borrada con éxito")

        except PermissionError:
            print("[ERROR] Fallo al tratar de borrar la BBDD anterior debido a la falta de permisos adecuados")
        except Exception as e:
            print(f"[ERROR] Fallo al tratar de borrar la BBDD anterior: {e}")

    # Creamos la BBDD así como las tablas para los archivos normales y los baseline
    con = sqlite3.connect('history/BBDD-local.db')
    # Comenzamos a crear las tablas
    try:
        cursor = con.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reportes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha DATE NOT NULL,
                datos_reporte JSON NOT NULL
                
            );
                       
            CREATE TABLE IF NOT EXISTS archivos_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha DATE NOT NULL,
                datos_baseline JSON NOT NULL                         
            );
        ''')
    except Exception as e:
        print(f"Se ha producido un error durante la creación de la BBDD: {e}")