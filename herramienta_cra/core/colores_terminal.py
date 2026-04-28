from colorama import init, Fore, Style, Back

init(autoreset=True)

def print_c(mensaje):

    # Si el mensaje empieza con tabulaciones o espacios, los conservamos
    espacios_iniciales = len(mensaje) - len(mensaje.lstrip())
    prefijo_espacios = " " * espacios_iniciales
    texto_limpio = mensaje.lstrip()

    if texto_limpio.startswith("[+]"):
        # Azul (CYAN brillante suele verse mejor en terminales oscuras)
        color = Fore.BLUE + Style.BRIGHT

    elif texto_limpio.startswith("[-]"):
        color = Fore.BLUE + Style.BRIGHT

    elif texto_limpio.startswith("[i]"):
        # Blanco o gris claro
        color = Fore.CYAN + Style.BRIGHT

    elif texto_limpio.startswith("[V]"):
        # Verde éxito
        color = Fore.GREEN + Style.BRIGHT

    elif texto_limpio.startswith("[!]"):
        # Amarillo advertencia
        color = Fore.YELLOW + Style.BRIGHT

    elif texto_limpio.startswith("[X]"):
        color = Fore.RED + Style.BRIGHT
    
    elif texto_limpio.startswith("[ERROR]"):
        # Rojo peligro
        color = Back.WHITE + Fore.RED + Style.BRIGHT
       
    else:
        # Texto normal
        color = Fore.WHITE

    # Imprimimos juntando los espacios originales + el color + el texto
    print(f"{prefijo_espacios}{color}{texto_limpio}{Style.RESET_ALL}")

def colorear_titulo():

    return