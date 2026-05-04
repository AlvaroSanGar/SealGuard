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
    # 1. TESTS DE: calcular_integridad()
    # =========================================================================
    @patch('os.stat')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b"datos_de_prueba")
    def test_calcular_hash_camino_feliz(self, mock_file, mock_exists, mock_stat):
        """Comprueba que devuelve el diccionario con hash, mtime y ctime"""
        mock_exists.return_value = True
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

    @patch('os.path.exists', return_value=True)
    @patch('os.stat')
    def test_calcular_hash_error_generico(self, mock_stat, mock_exists):
        """Comprueba el manejo de excepciones inesperadas (ej. fallo de disco)"""
        mock_stat.side_effect = Exception("Fallo critico de hardware")
        
        resultado = mIntegrity.calcular_integridad("/ruta/test")
        self.assertTrue(resultado.startswith("ERROR: Fallo critico"))

    # =========================================================================
    # 2. TESTS DE: generar_baseline()
    # =========================================================================
    @patch('modules.integrity.calcular_integridad')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_generar_baseline_feliz(self, mock_json_dump, mock_file, mock_calcular):
        """Comprueba que el baseline guarda los diccionarios correctamente"""
        mock_calcular.return_value = {"hash": "abcd", "mtime": 10.0, "ctime": 10.0}
        
        mIntegrity.generar_baseline()
        
        self.assertTrue(mock_json_dump.called)
        datos_guardados = mock_json_dump.call_args[0][0]
        self.assertEqual(len(datos_guardados), 3)
        self.assertIn("/etc/shadow", datos_guardados)

    @patch('modules.integrity.calcular_integridad')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_generar_baseline_ignora_errores(self, mock_json_dump, mock_file, mock_calcular):
        """Verifica que los archivos con error no se guardan en el baseline"""
        # Tenemos 3 rutas en MOCK_CONFIG. Simulamos error en la 1ª, éxito en la 2ª y None en la 3ª.
        mock_calcular.side_effect = ["FALTAN PERMISOS", {"hash": "ok", "mtime": 1, "ctime": 1}, None]
        
        mIntegrity.generar_baseline()
        
        datos_guardados = mock_json_dump.call_args[0][0]
        self.assertEqual(len(datos_guardados), 1)

    # =========================================================================
    # 3. TESTS DE: verificar_integridad()
    # =========================================================================
    @patch('os.path.exists')
    def test_verificar_integridad_sin_baseline(self, mock_exists):
        """No debe ejecutarse si no hay baseline anterior"""
        mock_exists.return_value = False
        res = mIntegrity.verificar_integridad(verbose=False)
        self.assertIsNone(res)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    @patch('modules.integrity.calcular_integridad')
    def test_verificar_integridad_detecta_cambios(self, mock_calcular, mock_json_load, mock_file, mock_exists):
        """Prueba central: ¿Detecta cuando mtime/ctime o el hash cambian?"""
        mock_json_load.return_value = {
            "/etc/shadow": {"hash": "hash_antiguo", "mtime": 1.0, "ctime": 1.0},
            "/bin/ls": {"hash": "mismo_hash", "mtime": 2.0, "ctime": 2.0}
        }
        
        def mock_calcular_side_effect(ruta):
            if ruta == "/etc/shadow":
                return {"hash": "hash_NUEVO", "mtime": 1.0, "ctime": 1.0}
            elif ruta == "/bin/ls":
                return {"hash": "mismo_hash", "mtime": 2.0, "ctime": 2.0}
            return None
                
        mock_calcular.side_effect = mock_calcular_side_effect
        resultados = mIntegrity.verificar_integridad(verbose=False)
        
        estado_shadow = next((item['estado'] for item in resultados if item['archivo'] == '/etc/shadow'), None)
        estado_ls = next((item['estado'] for item in resultados if item['archivo'] == '/bin/ls'), None)
        self.assertEqual(estado_shadow, "MODIFICADO")
        self.assertEqual(estado_ls, "INTACTO")

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    @patch('modules.integrity.calcular_integridad')
    def test_verificar_integridad_detalles_especificos(self, mock_calcular, mock_json_load, mock_file, mock_exists):
        """Verifica que identifica si cambió el hash, el mtime o el ctime de forma independiente"""
        mock_json_load.return_value = {
            "/etc/shadow": {"hash": "old_hash", "mtime": 10.0, "ctime": 10.0}
        }
        mock_calcular.return_value = {"hash": "old_hash", "mtime": 20.0, "ctime": 20.0}

        resultados = mIntegrity.verificar_integridad(verbose=False)
        # Buscamos el resultado del archivo shadow
        res_shadow = next(item for item in resultados if item['archivo'] == '/etc/shadow')
        detalles = res_shadow['detalles_cambio']

        self.assertEqual(res_shadow['estado'], "MODIFICADO")
        self.assertIn("mtime", detalles)
        self.assertIn("ctime", detalles)
        self.assertNotIn("hash", detalles)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    @patch('modules.integrity.calcular_integridad')
    def test_verificar_integridad_archivo_borrado(self, mock_calcular, mock_json_load, mock_file, mock_exists):
        """Verifica el estado cuando un archivo del baseline desaparece"""
        mock_json_load.return_value = {
            "/etc/shadow": {"hash": "abc", "mtime": 1.0, "ctime": 1.0}
        }
        mock_calcular.return_value = None 

        resultados = mIntegrity.verificar_integridad(verbose=False)
        res_shadow = next(item for item in resultados if item['archivo'] == '/etc/shadow')
        self.assertEqual(res_shadow['estado'], "INACCESIBLE / BORRADO")

if __name__ == '__main__':
    unittest.main(verbosity=2)