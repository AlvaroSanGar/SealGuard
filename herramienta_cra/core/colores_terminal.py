from colorama import init, Fore, Style, Back

init(autoreset=True)

def print_c(mensaje):

    # Si el mensaje empieza con tabulaciones o espacios, los conservamos
    espacios_iniciales = len(mensaje) - len(mensaje.lstrip())
    prefijo_espacios = " " * espacios_iniciales
    texto_limpio = mensaje.lstrip()

    if texto_limpio.startswith("[+]") or texto_limpio.startswith("- [+]"):
        # Azul (CYAN brillante suele verse mejor en terminales oscuras)
        color = Fore.BLUE + Style.BRIGHT
    elif texto_limpio.startswith("---- [ Escaneando"):
        # Azul para el titulo de escaneo
        color = Fore.BLUE + Style.BRIGHT

    elif texto_limpio.startswith("[-]") or texto_limpio.startswith("- [-]"):
        color = Fore.BLUE + Style.BRIGHT

    elif texto_limpio.startswith("[i]") or texto_limpio.startswith("- [i]"):
        # Blanco o gris claro
        color = Fore.CYAN + Style.BRIGHT

    elif texto_limpio.startswith("[Ok]") or texto_limpio.startswith("- [Ok]"):
        # Verde éxito
        color = Fore.GREEN + Style.BRIGHT

    elif texto_limpio.startswith("[!]") or texto_limpio.startswith("- [!]"):
        # Amarillo advertencia
        color = Fore.YELLOW + Style.BRIGHT

    elif texto_limpio.startswith("[X]") or texto_limpio.startswith("- [X]") or texto_limpio.startswith("\n    [TOP 5 HALLAZGOS CRÍTICOS]"):
        color = Fore.RED + Style.BRIGHT
    
    elif texto_limpio.startswith("[ERROR]") or texto_limpio.startswith("- [ERROR]"):
        # Rojo peligro
        color = Back.WHITE + Fore.RED + Style.BRIGHT
       
    else:
        # Texto normal
        color = Fore.LIGHTWHITE_EX

    # Imprimimos juntando los espacios originales + el color + el texto
    print(f"{prefijo_espacios}{color}{texto_limpio}{Style.RESET_ALL}")

def colorear_titulo():

    return


def print_table(mensaje):
    
    print(Fore.CYAN+Style.BRIGHT+mensaje)
    
def print_input(mensaje):
    return input(Fore.CYAN+Style.BRIGHT+mensaje)


def mostrar_banner():
    logo_ascii = """
 ██████╗ ███████╗ █████╗ ██╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔════╝ ██╔════╝██╔══██╗██║     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
███████╗ █████╗  ███████║██║     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
╚════██║ ██╔══╝  ██╔══██║██║     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
███████║ ███████╗██║  ██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚══════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
    """
    
    print(Fore.CYAN + Style.BRIGHT + logo_ascii + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "    CYBERSECURITY AUDITOR")
    print(Fore.LIGHTBLUE_EX + "    Herramienta de Auditoría CRA - TFG UCLM\n")
    
    
def mostrar_subtitulos(mensaje):
    BANNERS_FASES = {
    "Networking": r"""
 █▄░█ █▀▀ ▀█▀ █░█░█ █▀█ █▀█ █▄▀ █ █▄░█ █▀▀
 █░▀█ ██▄ ░█░ ▀▄▀▄▀ █▄█ █▀▄ █░█ █ █░▀█ █▄█
 -----------------------------------------
""",
    "Vulnerabilidades": r"""
 █░█ █░█ █░░ █▄░█ █▀▀ █▀█ █▀█ █▄▄ █ █░░ █ █▀▄ █▀█ █▀▄ █▀▀ █▀▀
 ▀▄▀ █▄█ █▄▄ █░▀█ ██▄ █▀▄ █▀█ █▄█ █ █▄▄ █ █▄▀ █▀█ █▄▀ ██▄ ▄██
 -----------------------------------------------------------
""",
    "Integridad": r"""
 █ █▄░█ ▀█▀ █▀▀ █▀▀ █▀█ █ █▀▄ █▀█ █▀▄
 █ █░▀█ ░█░ ██▄ █▄█ █▀▄ █ █▄▀ █▀█ █▄▀
 ----------------------------------
""",
    "Usuarios": r"""
 █░█ █▀▀ █░█ █▀█ █▀█ █ █▀█ █▀▀
 █▄█ ▄██ █▄█ █▀█ █▀▄ █ █▄█ ▄██
 ----------------------------
""",
    "Hardening": r"""
 █░█ █▀█ █▀█ █▀▄ █▀▀ █▄░█ █ █▄░█ █▀▀
 █▀█ █▀█ █▀▄ █▄▀ ██▄ █░▀█ █ █░▀█ █▄█
 ----------------------------------
""",
    "Booting": r"""
 █▄▄ █▀█ █▀█ ▀█▀ █ █▄░█ █▀▀
 █▄█ █▄█ █▄█ ░█░ █ █░▀█ █▄█
 -------------------------
""",
    "Disponibilidad": r"""
 █▀▄ █ █▀▀ █▀█ █▀█ █▄░█ █ █▄▄ █ █░░ █ █▀▄ █▀█ █▀▄
 █▄▀ █ ▄██ █▀▀ █▄█ █░▀█ █ █▄█ █ █▄▄ █ █▄▀ █▀█ █▄▀
 ----------------------------------------------
"""
}
    print(Fore.CYAN+Style.BRIGHT+BANNERS_FASES[mensaje])