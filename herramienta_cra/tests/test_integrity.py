import unittest
from unittest.mock import patch, MagicMock, mock_open
import json
import hashlib

# Importamos tu módulo
import modules.integrity as mIntegrity

class TestIntegrityModule(unittest.TestCase):

    # -------------------------------------------------------------------
    # PRUEBAS PARA: calcular_hash(ruta)
    # -------------------------------------------------------------------

    @patch('modules.integrity.os.path.exists', return_value=False)
    def test_calcular_hash_no_existe(self, mock_exists):
        """Camino Triste: El archivo no existe"""
        resultado = mIntegrity.calcular_hash('/ruta/falsa.txt')
        self.assertIsNone(resultado)

    @patch('modules.integrity.os.path.exists', return_value=True)
    @patch('builtins.open', side_effect=PermissionError)
    def test_calcular_hash_sin_permisos(self, mock_open_func, mock_exists):
        """Camino Triste: El usuario no es root y no tiene permisos"""
        resultado = mIntegrity.calcular_hash('/etc/shadow')
        self.assertEqual(resultado, "FALTAN PERMISOS")

    @patch('modules.integrity.os.path.exists', return_value=True)
    # mock_open simula abrir un archivo y leer los bytes que le pongamos en 'read_data'
    @patch('builtins.open', new_callable=mock_open, read_data=b"texto de prueba")
    def test_calcular_hash_exito(self, mock_open_func, mock_exists):
        """Camino Feliz: Calcula el hash SHA-256 de un archivo"""
        resultado = mIntegrity.calcular_hash('/etc/passwd')
        
        # El SHA-256 de "texto de prueba" es exactamente este:
        hash_esperado = hashlib.sha256(b"texto de prueba").hexdigest()
        self.assertEqual(resultado, hash_esperado)


    # -------------------------------------------------------------------
    # PRUEBAS PARA: generar_baseline()
    # -------------------------------------------------------------------

    # AHORA EL MOCK TIENE LAS 3 LISTAS QUE BUSCA TU CÓDIGO
    @patch('modules.integrity.config', {
        'system': {'critical_files': [{'path': '/etc/test_critico'}]},
        'integrity': {
            'monitored_binaries': ['/bin/test_binario'],
            'monitored_configs': ['/etc/test_config']
        }
    })
    @patch('modules.integrity.calcular_hash', return_value="hash_falso_123")
    @patch('builtins.open', new_callable=mock_open)
    def test_generar_baseline_exito(self, mock_open_func, mock_calc_hash):
        """Camino Feliz: Genera el baseline y lo guarda en JSON"""
        
        mIntegrity.generar_baseline()
        
        # Verificamos que se han hasheado exactamente los 3 archivos que le hemos pasado en el Mock
        self.assertEqual(mock_calc_hash.call_count, 3)
        # Comprobamos que intentó abrir el archivo correcto en modo escritura 'w'
        mock_open_func.assert_called_with('history/escaneo_baseline.json', 'w')


    # -------------------------------------------------------------------
    # PRUEBAS PARA: verificar_integridad(verbose)
    # -------------------------------------------------------------------

    @patch('modules.integrity.os.path.exists', return_value=False)
    def test_verificar_integridad_sin_baseline(self, mock_exists):
        """Camino Triste: Falla si no se ha ejecutado el baseline primero"""
        resultado = mIntegrity.verificar_integridad(verbose=False)
        self.assertIsNone(resultado)

    @patch('modules.integrity.os.path.exists', return_value=True)
    @patch('modules.integrity.config', {
        'system': {
            'critical_files': [{'path': '/etc/intacto'}]
        },
        'integrity': {
            'monitored_binaries': ['/bin/modificado', '/bin/nuevo'], # /bin/nuevo no estará en el baseline
            'monitored_configs': []
        }
    })
    def test_verificar_integridad_logica_completa(self, mock_exists):
        """Camino Complejo: Comprueba los 4 estados posibles de la comparativa."""
        
        # 1. Simulamos el contenido del archivo JSON guardado (El Baseline)
        datos_guardados = {
            "/etc/intacto": "hash_111",
            "/bin/modificado": "hash_222",
            "/bin/borrado": "hash_333" # Este está guardado, pero ya no existe en la config mockeada
        }
        
        # Simulamos la lectura del json.load
        mock_json_load = patch('modules.integrity.json.load', return_value=datos_guardados)
        
        # 2. Simulamos lo que calcula la función calcular_hash EN VIVO
        def mock_calcular_hash(ruta):
            if ruta == "/etc/intacto": return "hash_111"       # Coincide -> INTACTO
            if ruta == "/bin/modificado": return "hash_NUEVO"  # Distinto -> MODIFICADO
            if ruta == "/bin/nuevo": return "hash_444"         # -> NO_RASTREADO
            return None # Por si acaso
            
        mock_calc = patch('modules.integrity.calcular_hash', side_effect=mock_calcular_hash)
        
        # Necesitamos usar el mock de open para pasar el 'with open' sin que explote
        mock_file = patch('builtins.open', new_callable=mock_open)

        # Activamos los parches y ejecutamos
        with mock_json_load, mock_calc, mock_file:
            resultados = mIntegrity.verificar_integridad(verbose=False)
            
        # 3. Comprobaciones de la lógica
        estados = { r['archivo']: r['estado'] for r in resultados }
        
        self.assertEqual(estados['/etc/intacto'], "INTACTO")
        self.assertEqual(estados['/bin/modificado'], "MODIFICADO")
        self.assertEqual(estados['/bin/borrado'], "INACCESIBLE / BORRADO")
        self.assertEqual(estados['/bin/nuevo'], "NO_RASTREADO")

if __name__ == '__main__':
    unittest.main()