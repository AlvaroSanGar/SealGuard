import unittest
from unittest.mock import patch, mock_open, MagicMock
import os

# Importación de las funciones del módulo booting
from modules.booting import (
    auditar_integridad_firmware, auditar_parametros_kernel, 
    auditar_seguridad_grub, ESCANER_booting
)

# Configuración Mock Completa y Corregida
BOOT_CONFIG_MOCK = {
    "boot": {
        "integridad_kernel": {
            "white_list": [["P", 1, "Módulo propietario"], ["O", 4096, "Módulo externo"]],
            "warning_list": [["W", 512, "Warning"], ["C", 1024, "Staging"], ["K", 32768, "Livepatch"]],
            "black_list": [["F", 2, "Forzado"], ["R", 8, "Unload"], ["E", 8192, "No firmado"]]
        },
        "param_kernel": {
            "white_list": [["apparmor=1", "selinux=1"], "audit=1", "slab_nomerge=1"],
            "black_list": [["init=/bin/bash", "single"], "nokaslr", ["mitigations=off", "nopti"]]
        },
        "contra_fisica": True
    }
}

@patch.dict('modules.booting.config', BOOT_CONFIG_MOCK, clear=True)
class TestBootingMasivo(unittest.TestCase):

    # --- 1. INTEGRIDAD DE FIRMWARE (8 Tests) ---

    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_perfecta(self, mock_db):
        """Secure Boot Full y Kernel limpio"""
        mock_db.side_effect = [[{"secure_boot": 1}], [{"current_value": "0"}]]
        res = auditar_integridad_firmware(False)
        self.assertEqual(res["sb_estado"], "SEGURO")
        self.assertTrue(res["kernel_seguro"])

    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_sb_medium(self, mock_db):
        """Secure Boot en modo Medium-Security (Valor 2)"""
        mock_db.side_effect = [[{"secure_boot": 2}], [{"current_value": "0"}]]
        res = auditar_integridad_firmware(False)
        self.assertEqual(res["sb_estado"], "ADVERTENCIA")

    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_sb_off(self, mock_db):
        """Secure Boot desactivado en sistema UEFI[cite: 5]"""
        mock_db.side_effect = [[{"secure_boot": 0}], [{"current_value": "0"}]]
        res = auditar_integridad_firmware(False)
        self.assertEqual(res["sb_estado"], "PELIGROSO")

    @patch('modules.booting.ejecutar_consulta', return_value=[])
    def test_integridad_legacy_mode(self, mock_db):
        """Detección de arranque en modo Legacy[cite: 5]"""
        res = auditar_integridad_firmware(False)
        self.assertEqual(res["sb_estado"], "PELIGROSO")
        self.assertTrue(any("Legacy" in a for a in res["alertas"]))

    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_kernel_flags_mixtas(self, mock_db):
        """Detección de múltiples flags (P, W, E)[cite: 5]"""
        mock_db.side_effect = [[{"secure_boot": 1}], [{"current_value": str(1 + 512 + 8192)}]]
        res = auditar_integridad_firmware(False)
        self.assertEqual(len(res["tainted_flags"]), 3)
        self.assertTrue(any("fallo crítico" in a for a in res["alertas"]))

    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_kernel_flags_desconocidas(self, mock_db):
        """Kernel alterado pero con flags no listadas[cite: 5]"""
        mock_db.side_effect = [[{"secure_boot": 1}], [{"current_value": "1048576"}]] # Flag 2^20
        res = auditar_integridad_firmware(False)
        self.assertTrue(res["kernel_seguro"]) # problemas_tai es 0

    @patch('modules.booting.ejecutar_consulta', return_value=[])
    @patch('modules.booting.config', {})
    def test_integridad_keyerror_fallback(self, mock_db):
        """Uso de valores por defecto si falla el config.yaml[cite: 5]"""
        res = auditar_integridad_firmware(False)
        self.assertTrue(any("No se ha encontrado la configuración" in d for d in res["detalles"]))

    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_tainted_vacio(self, mock_db):
        """Fallo en la obtención del valor 'tainted'[cite: 5]"""
        mock_db.side_effect = [[{"secure_boot": 1}], []]
        res = auditar_integridad_firmware(False)
        self.assertTrue(any("No se ha logrado obtener el valor" in a for a in res["alertas"]))

    # --- 2. PARÁMETROS DEL KERNEL (10 Tests) ---

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX="apparmor=1 audit=1 slab_nomerge=1"\n')
    def test_params_seguros_en_linux(self, mock_file, mock_exists):
        """Configuración óptima persistente[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 audit=1 slab_nomerge=1"\n')
    def test_params_advertencia_default(self, mock_file, mock_exists):
        """CORREGIDO: Parámetros en DEFAULT (incluyendo todos los obligatorios)[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "ADVERTENCIA")

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX="init=/bin/bash"\n')
    def test_params_prohibidos_blacklist(self, mock_file, mock_exists):
        """Detección de parámetros prohibidos críticos[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertTrue(len(res["prohibido"]) > 0)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX="nokaslr mitigations=off"\n')
    def test_params_blacklist_grupo(self, mock_file, mock_exists):
        """Detección de múltiples parámetros prohibidos en grupo[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(len(res["prohibido"]), 2)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX="selinux=1 audit=1 slab_nomerge=1"\n')
    def test_params_lista_opciones_or(self, mock_file, mock_exists):
        """Uso de alternativa válida en la white_list[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX=" apparmor=1   audit=1   slab_nomerge=1 "\n')
    def test_params_parsing_espacios(self, mock_file, mock_exists):
        """Robustez del parseo ante espacios extra[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX="apparmor=1"\n')
    def test_params_solo_uno_de_muchos(self, mock_file, mock_exists):
        """Fallo si solo se configura uno de los tres parámetros obligatorios[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertEqual(len(res["fallos"]), 2)

    @patch('os.path.exists', return_value=False)
    def test_params_no_grub_file(self, mock_exists):
        """Falta del archivo /etc/default/grub[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "NO ENCONTRADO")

    @patch('os.path.exists', return_value=True)
    def test_params_excepcion_lectura(self, mock_exists):
        """Error de entrada/salida al leer el archivo[cite: 5]"""
        with patch('builtins.open', side_effect=IOError("Error E/S")):
            res = auditar_parametros_kernel(False)
            self.assertTrue(any("No se ha logrado leer" in a for a in res["alertas"]))

    @patch('modules.booting.config', {"boot": {}})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX="audit=1"\n')
    def test_params_config_vacia_fallback(self, mock_file, mock_exists):
        """Uso de white_list hardcodeada si falla el config[cite: 5]"""
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "PELIGROSO") # Fallará porque faltan selinux/apparmor

    # --- 3. SEGURIDAD GRUB (8 Tests) ---

    def test_grub_hardening_no_encontrado(self):
        """Sin datos de auditoría de permisos previa[cite: 5]"""
        res = auditar_seguridad_grub(False, None)
        self.assertEqual(res["archivo_estado"], "NO ENCONTRADO")

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='password_pbkdf2 root hash\n')
    def test_grub_seguro_completo(self, mock_file, mock_exists):
        """Permisos OK y contraseña cifrada activa[cite: 5]"""
        datos = {"estado": "SEGURO", "archivo": "/boot/grub/grub.cfg"}
        res = auditar_seguridad_grub(False, datos)
        self.assertEqual(res["estado"], "SEGURO")
        self.assertTrue(res["protegido"])

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='timeout=5\n')
    def test_grub_peligroso_sin_pass(self, mock_file, mock_exists):
        """Permisos OK pero falta seguridad física obligatoria[cite: 5]"""
        datos = {"estado": "SEGURO", "archivo": "/boot/grub/grub.cfg"}
        res = auditar_seguridad_grub(False, datos)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertEqual(res["pass_estado"], "ADVERTENCIA")

    @patch('modules.booting.config', {"boot": {"contra_fisica": False}})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='timeout=5\n')
    def test_grub_ok_sin_requisito_pass(self, mock_file, mock_exists):
        """Seguro si el usuario decide no exigir contraseña física[cite: 5]"""
        datos = {"estado": "SEGURO", "archivo": "/boot/grub/grub.cfg"}
        res = auditar_seguridad_grub(False, datos)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='password_pbkdf2 user hash\n')
    def test_grub_config_path_grub2(self, mock_file, mock_exists):
        """Soporte para rutas alternativas (RedHat/CentOS)[cite: 5]"""
        mock_exists.side_effect = lambda p: p == '/boot/grub2/grub.cfg'
        datos = {"estado": "SEGURO", "archivo": "/boot/grub2/grub.cfg"}
        res = auditar_seguridad_grub(False, datos)
        self.assertEqual(res["pass_estado"], "SEGURO")

    @patch('os.path.exists', return_value=True)
    def test_grub_open_exception_handling(self, mock_exists):
        """Captura de errores al abrir el archivo de configuración[cite: 5]"""
        with patch('builtins.open', side_effect=Exception("Error fatal")):
            datos = {"estado": "SEGURO", "archivo": "/boot/grub/grub.cfg"}
            res = auditar_seguridad_grub(False, datos)
            self.assertFalse(res["protegido"])

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='password_pbkdf2 root hash\n')
    def test_grub_hardening_peligroso_permisos(self, mock_file, mock_exists):
        """Estado PELIGROSO si los permisos del archivo son inseguros[cite: 5]"""
        datos = {"estado": "PELIGROSO", "problemas": ["Permisos 777"]}
        res = auditar_seguridad_grub(False, datos)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertEqual(res["archivo_estado"], "PELIGROSO")

    @patch('os.path.exists', return_value=False)
    def test_grub_cfg_no_encontrado(self, mock_exists):
        """Alerta si el archivo compilado .cfg no existe[cite: 5]"""
        datos = {"estado": "SEGURO", "archivo": "/boot/grub/grub.cfg"}
        res = auditar_seguridad_grub(False, datos)
        self.assertTrue(any("No se encontró el archivo compilado" in a for a in res["alertas"]))

    # --- 4. ORQUESTADOR (1 Test) ---

    @patch('modules.booting.auditar_integridad_firmware', return_value={"mock": 1})
    @patch('modules.booting.auditar_parametros_kernel', return_value={"mock": 2})
    @patch('modules.booting.auditar_seguridad_grub', return_value={"mock": 3})
    def test_escaner_booting_integration(self, m1, m2, m3):
        """Verificación de la salida consolidada del orquestador[cite: 5]"""
        res = ESCANER_booting(False, {})
        self.assertEqual(res["integridad"]["mock"], 1)
        self.assertEqual(res["parametros"]["mock"], 2)
        self.assertEqual(res["grub"]["mock"], 3)

if __name__ == '__main__':
    unittest.main(verbosity=2)