import yaml
import sys 


def loadYaml(path):
    try:
        with open(path,"r", encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    except FileNotFoundError:
        print('Error al cargar el yaml, archivo no encontrado\n')
        sys.exit(1)
    
    except yaml.YAMLError:
        print("El archivo yaml contiene errores\n")
        sys.exit(1)
        
config = loadYaml("config/controls.yaml")