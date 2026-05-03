import unittest
from unittest.mock import patch, mock_open, MagicMock
import json
import modules.integrity as mIntegrity

# Mockeamos el settings.yaml para no depender de archivos reales
MOCK_CONFIG = {
    "hardening": {  
        "critical_files": [{"path": "/etc/shadow"}]
    },
    "integrity": {
        "monitored_binaries": ["/bin/ls"],
        "monitored_configs": ["/etc/hosts"]
    }
}

@patch.dict('modules.integrity.config', MOCK_CONFIG, clear=True)
class TestIntegridadModulo(unittest.TestCase):

    # =========================================================================
    # 1. TESTS DE: calcular_hash()
    # =========================================================================
    @patch('os.stat')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b"datos_de_prueba")
    def test_calcular_hash_camino_feliz(self, mock_file, mock_exists, mock_stat):
        """Comprueba que devuelve el diccionario con hash, mtime y ctime"""
        mock_exists.return_value = True
        
        # Simulamos los tiempos del sistema operativo
        mock_stat.return_value.st_mtime = 1600000000.0
        mock_stat.return_value.st_ctime = 1600000005.0
        
        resultado = mIntegrity.calcular_integridad("/ruta/falsa")
        
        self.assertIsInstance(resultado, dict)
        self.assertIn("hash", resultado)
        self.assertEqual(resultado["mtime"], 1600000000.0)
        self.assertEqual(resultado["ctime"], 1600000005.0)

    @patch('os.path.exists')
    def test_calcular_hash_no_existe(self, mock_exists):
        """Comprueba qué pasa si el archivo no existe"""
        mock_exists.return_value = False
        resultado = mIntegrity.calcular_integridad("/ruta/falsa")
        self.assertIsNone(resultado)

    @patch('os.stat')
    @patch('os.path.exists')
    @patch('builtins.open')
    def test_calcular_hash_sin_permisos(self, mock_file, mock_exists, mock_stat):
        """Comprueba manejo de PermissionError"""
        mock_exists.return_value = True
        mock_file.side_effect = PermissionError()
        
        resultado = mIntegrity.calcular_integridad("/ruta/falsa")
        self.assertEqual(resultado, "FALTAN PERMISOS")

    # =========================================================================
    # 2. TESTS DE: generar_baseline()
    # =========================================================================
    @patch('modules.integrity.calcular_integridad')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_generar_baseline_feliz(self, mock_json_dump, mock_file, mock_calcular):
        """Comprueba que el baseline guarda los diccionarios correctamente"""
        # Simulamos que calcular_hash devuelve la nueva estructura
        mock_calcular.return_value = {"hash": "abcd", "mtime": 10.0, "ctime": 10.0}
        
        mIntegrity.generar_baseline()
        
        # Comprobamos que intentó escribir el JSON
        self.assertTrue(mock_json_dump.called)
        
        # Obtenemos los argumentos con los que se llamó a json.dump
        datos_guardados = mock_json_dump.call_args[0][0]
        
        # Debería haber 3 archivos según nuestro MOCK_CONFIG (/etc/shadow, /bin/ls, /etc/hosts)
        self.assertEqual(len(datos_guardados), 3)
        self.assertIn("/etc/shadow", datos_guardados)
        self.assertEqual(datos_guardados["/etc/shadow"]["hash"], "abcd")

    # =========================================================================
    # 3. TESTS DE: verificar_integridad()
    # =========================================================================
    @patch('os.path.exists')
    def test_verificar_integridad_sin_baseline(self, mock_exists):
        """No debe ejecutarse si no hay baseline anterior"""
        mock_exists.return_value = False
        res = mIntegrity.verificar_integridad(verbose=False)
        self.assertIsNone(res)

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    @patch('modules.integrity.calcular_integridad')
    def test_verificar_integridad_detecta_cambios(self, mock_calcular, mock_json_load, mock_file, mock_exists):
        """Prueba central: ¿Detecta cuando mtime/ctime o el hash cambian?"""
        mock_exists.return_value = True
        
        # Simulamos el contenido del archivo JSON antiguo (Baseline)
        mock_json_load.return_value = {
            "/etc/shadow": {"hash": "hash_antiguo", "mtime": 1.0, "ctime": 1.0},
            "/bin/ls": {"hash": "mismo_hash", "mtime": 2.0, "ctime": 2.0}
        }
        
        # Simulamos lo que lee el sistema AHORA (calcular_hash)
        def mock_calcular_side_effect(ruta):
            if ruta == "/etc/shadow":
                # MODIFICADO: El hash cambió
                return {"hash": "hash_NUEVO", "mtime": 1.0, "ctime": 1.0}
            elif ruta == "/bin/ls":
                # INTACTO: Todo es exactamente igual
                return {"hash": "mismo_hash", "mtime": 2.0, "ctime": 2.0}
            else:
                # NO_RASTREADO: Un archivo que no estaba en el JSON antiguo
                return {"hash": "x", "mtime": 0, "ctime": 0}
                
        mock_calcular.side_effect = mock_calcular_side_effect

        resultados = mIntegrity.verificar_integridad(verbose=False)
        
        # Buscamos los estados en el resultado
        estado_shadow = next((item['estado'] for item in resultados if item['archivo'] == '/etc/shadow'), None)
        estado_ls = next((item['estado'] for item in resultados if item['archivo'] == '/bin/ls'), None)
        estado_hosts = next((item['estado'] for item in resultados if item['archivo'] == '/etc/hosts'), None)

        self.assertEqual(estado_shadow, "MODIFICADO")
        self.assertEqual(estado_ls, "INTACTO")
        self.assertEqual(estado_hosts, "NO_RASTREADO")

if __name__ == '__main__':
    unittest.main(verbosity=2)