from modules.network import scaneoPuertos
import socket


ip = "10.0.2.4"
verbose = True
if __name__ == "__main__":
    # Capturamos los resultados en una variable
    resultado = scaneoPuertos(ip, verbose)
    
    # Debuggear resultado
    print("\n\n-----------------------DEBUGGEAR-------------------------\n")
    print(resultado)