import argparse
import sys
import os
import subprocess
from core.auditor import seleccionar
from core.colores_terminal import mostrar_banner, print_c, print_table

# Creamos una clase personalizada para "secuestrar" los mensajes y la ayuda
class CustomArgumentParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        # Obtenemos el texto del menú de ayuda como un string
        help_text = self.format_help()
        # Imprimimos línea por línea usando tu función de colores
        for line in help_text.splitlines():
            print_table(line)

    def error(self, message):
        # Cuando hay un error, mostramos la ayuda con nuestra función sobreescrita
        self.print_help()
        sys.exit(2)



def main():
    # Usamos nuestro parser personalizado
    parser = CustomArgumentParser(
        description="SealGuard - Auditoría Técnica de Ciberresiliencia (CRA)",
        epilog="Ejemplo de uso: ./sealguard --mode=scan --verbose=True",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "--mode", 
        type=str, 
        required=True, 
        choices=["scan", "baseline", "config-bl", "recover", "history", "delete", "edit-config"],
        help=(
            "Modo de ejecución de la herramienta:\n"
            "  scan        - Ejecuta un escaneo completo\n"
            "  baseline    - Genera un archivo baselinede integridad\n"
            "  config-bl   - Selecciona un archivo baseline\n"
            "  recover     - Recupera un reporte anterior en PDF\n"
            "  history     - Muestra el contenido de la BBDD\n"
            "  delete      - Borra la BBDD local\n"
            "  edit-config - Abre el archivo YAML para personalizar la herramienta"
        )
    )
    
    parser.add_argument(
        "--verbose",
        type=str,
        default="True",
        choices=["True", "False", "true", "false"],
        help="Activa o desactiva la salida detallada en terminal (por defecto: True)"
    )

    # Si el usuario no introduce ningún argumento, usamos nuestro print_help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Parseamos los argumentos introducidos
    args = parser.parse_args()

    # Convertimos el string de verbose a un booleano real de Python
    verbose_bool = args.verbose.lower() == "true"

    mostrar_banner()

    # Opción para editar el YAML
    if args.mode == "edit-config":
        print_c("[+] Abriendo el archivo de configuración")
        editor = os.environ.get('EDITOR', 'nano') 
        subprocess.call([editor, 'config/controls.yaml'])
        print_c("[-] Configuración guardada")
        sys.exit(0)

    # Flujo normal
    seleccionar(args.mode, verbose_bool)

if __name__ == "__main__":
    main()