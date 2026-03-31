import unittest
from unittest.mock import patch, mock_open, MagicMock

# Importación real apuntando a modules/booting.py
from modules.booting import (
    auditar_integridad_firmware, auditar_parametros_kernel, 
    auditar_seguridad_grub, ESCANER_booting
)

# Constantes estáticas para evitar el error de los decoradores al inyectar configuraciones
BOOT_CONFIG_MOCK = {
    "boot": {
        "integridad_kernel": {
            "white_list": [["P", 1], ["O", 4096]],
            "warning_list": [["W", 512], ["C", 1024], ["K", 32768]],
            "black_list": [["F", 2], ["R", 8], ["D", 128], ["A", 256], ["E", 8192]]
        },
        "param_kernel": {
            "white_list": [["apparmor=1", "selinux=1"], "audit=1"],
            "black_list": ["init=/bin/bash", "nokaslr"]
        },
        "contra_fisica": True
    }
}

class TestBootingCompleto(unittest.TestCase):

    # =====================================================================
    # 1. TESTS: INTEGRIDAD DEL FIRMWARE (auditar_integridad_firmware)
    # =====================================================================
    @patch('modules.booting.config', BOOT_CONFIG_MOCK)
    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_perfecta(self, mock_db):
        # SecureBoot activo (1) y Kernel impecable (0)
        def side_effect(query):
            if 'secureboot' in query: return [{"secure_boot": 1}]
            if 'kernel.tainted' in query: return [{"current_value": "0"}]
            return []
        mock_db.side_effect = side_effect
        
        res = auditar_integridad_firmware(False)
        self.assertTrue(res["secure_boot"])
        self.assertTrue(res["kernel_seguro"])
        self.assertEqual(len(res["alertas"]), 0)

    @patch('modules.booting.config', BOOT_CONFIG_MOCK)
    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_legacy_y_kernel_corrupto(self, mock_db):
        # Sin tabla secureboot (Legacy) y Kernel con error crítico (8192 -> E) y warning (512 -> W)
        def side_effect(query):
            if 'secureboot' in query: return [] # Falla secureboot
            if 'kernel.tainted' in query: return [{"current_value": str(8192 + 512)}] 
            return []
        mock_db.side_effect = side_effect
        
        res = auditar_integridad_firmware(False)
        self.assertFalse(res["secure_boot"])
        self.assertFalse(res["kernel_seguro"])
        self.assertTrue(any("Legacy" in a for a in res["alertas"]))
        self.assertTrue(any("fallo crítico" in a for a in res["alertas"])) # Caza el 8192
        self.assertTrue(any("peligrosidad media" in a for a in res["alertas"])) # Caza el 512

    @patch('modules.booting.config', BOOT_CONFIG_MOCK)
    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_fallback_osquery_vacio(self, mock_db):
        # Simula que OSquery no logra leer el valor tainted
        def side_effect(query):
            if 'secureboot' in query: return [{"secure_boot": 2}] # Medium Security
            if 'kernel.tainted' in query: return [] # Falla query
            return []
        mock_db.side_effect = side_effect
        
        res = auditar_integridad_firmware(False)
        self.assertTrue(any("Medium-Security" in a for a in res["alertas"]))
        self.assertTrue(any("No se ha logrado obtener el valor" in a for a in res["alertas"]))

    @patch('modules.booting.config', {}) # Forzamos el KeyError pasando un diccionario vacío
    @patch('modules.booting.ejecutar_consulta')
    def test_integridad_keyerror_fallback(self, mock_db):
        # Prueba que el código no explote si falta el config.yaml y cargue los valores hardcodeados
        mock_db.side_effect = lambda q: [{"secure_boot": 1}] if 'secure' in q else [{"current_value": "0"}]
        res = auditar_integridad_firmware(False)
        self.assertTrue(res["kernel_seguro"])


    # =====================================================================
    # 2. TESTS: PARÁMETROS DEL KERNEL (auditar_parametros_kernel)
    # =====================================================================
    @patch('modules.booting.config', BOOT_CONFIG_MOCK)
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX="apparmor=1 audit=1"\nGRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\n')
    def test_parametros_kernel_seguro(self, mock_archivo, mock_exists):
        # Opciones obligatorias están en LINUX, no hay prohibidas
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "SEGURO")
        self.assertEqual(len(res["fallos"]), 0)

    @patch('modules.booting.config', BOOT_CONFIG_MOCK)
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX=""\nGRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 audit=1"\n')
    def test_parametros_kernel_advertencia(self, mock_archivo, mock_exists):
        # Las opciones están en DEFAULT y no en LINUX (Genera Advertencia según tu lógica)
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "ADVERTENCIA")
        self.assertTrue(len(res["alertas"]) > 0)

    @patch('modules.booting.config', BOOT_CONFIG_MOCK)
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='GRUB_CMDLINE_LINUX="init=/bin/bash"\nGRUB_CMDLINE_LINUX_DEFAULT="quiet"\n')
    def test_parametros_kernel_peligroso(self, mock_archivo, mock_exists):
        # Faltan opciones seguras y hay una prohibida (black_list)
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertTrue(len(res["fallos"]) > 0)
        self.assertTrue(len(res["prohibido"]) > 0)

    @patch('modules.booting.config', BOOT_CONFIG_MOCK)
    @patch('os.path.exists', return_value=False)
    def test_parametros_kernel_no_existe(self, mock_exists):
        # Archivo grub no existe
        res = auditar_parametros_kernel(False)
        self.assertEqual(res["estado"], "NO ENCONTRADO")

    @patch('modules.booting.config', BOOT_CONFIG_MOCK)
    @patch('os.path.exists', return_value=True)
    def test_parametros_kernel_excepcion_lectura(self, mock_exists):
        # Archivo existe pero lanza error al leer (ej. falta de permisos)
        with patch('builtins.open', side_effect=IOError("Permiso denegado")):
            res = auditar_parametros_kernel(False)
            self.assertTrue(any("No se ha logrado leer" in a for a in res["alertas"]))


    # =====================================================================
    # 3. TESTS: SEGURIDAD GRUB (auditar_seguridad_grub)
    # =====================================================================
    @patch('modules.booting.config', BOOT_CONFIG_MOCK) # contra_fisica = True
    def test_seguridad_grub_datos_faltantes(self):
        # Viene del módulo hardening como no encontrado o None
        res = auditar_seguridad_grub(False, {"estado": "NO ENCONTRADO"})
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertTrue(any("no fue encontrado" in a for a in res["alertas"]))

    @patch('modules.booting.config', BOOT_CONFIG_MOCK) 
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='set superusers="root"\npassword_pbkdf2 root grub.pbkdf2.sha512...\n')
    def test_seguridad_grub_perfecto(self, mock_archivo, mock_exists):
        # Hardening dice OK, archivo de config existe y tiene password_pbkdf2
        mock_exists.side_effect = lambda path: path == '/boot/grub/grub.cfg' # Simula Debian/Ubuntu
        datos_hardening = {"estado": "SEGURO", "archivo": "/boot/grub/grub.cfg"}
        
        res = auditar_seguridad_grub(False, datos_hardening)
        self.assertEqual(res["estado"], "SEGURO")
        self.assertTrue(res["protegido"])
        self.assertTrue(res["permisos_ok"])

    @patch('modules.booting.config', BOOT_CONFIG_MOCK) 
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='set timeout=5\n')
    def test_seguridad_grub_sin_password_pero_hardening_ok(self, mock_archivo, mock_exists):
        # Permisos OK, pero no hay contraseña. Como la config exige contra_fisica=True, debe fallar.
        mock_exists.side_effect = lambda path: path == '/boot/grub2/grub.cfg' # Simula RedHat
        datos_hardening = {"estado": "SEGURO", "archivo": "/boot/grub/grub.cfg"}
        
        res = auditar_seguridad_grub(False, datos_hardening)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertFalse(res["protegido"])
        self.assertTrue(res["permisos_ok"])

    @patch('modules.booting.config', {"boot": {"contra_fisica": False}}) 
    @patch('os.path.exists', return_value=False)
    def test_seguridad_grub_excepcion_no_requiere_password(self, mock_exists):
        # Permisos OK, el archivo grub.cfg ni se encuentra, PERO el yaml dice que no requiere password
        datos_hardening = {"estado": "SEGURO", "archivo": "/boot/grub/grub.cfg"}
        res = auditar_seguridad_grub(False, datos_hardening)
        # La lógica de tu código dice: elif resultados["permisos_ok"] and not contra -> SEGURO
        self.assertEqual(res["estado"], "SEGURO")

    @patch('modules.booting.config', BOOT_CONFIG_MOCK) 
    def test_seguridad_grub_problemas_hardening(self):
        # Viene del módulo hardening con problemas de permisos
        datos_hardening = {"estado": "PELIGROSO", "problemas": ["El dueño esperado es root", "Permisos excesivos"]}
        # Mockeamos exists a False para forzar salto directo
        with patch('os.path.exists', return_value=False):
            res = auditar_seguridad_grub(False, datos_hardening)
            self.assertEqual(res["estado"], "PELIGROSO")
            self.assertFalse(res["permisos_ok"])
            self.assertEqual(len(res["alertas"]), 3) # 2 del hardening + 1 de archivo grub no encontrado


    # =====================================================================
    # 4. TESTS: ESCÁNER PRINCIPAL (ESCANER_booting)
    # =====================================================================
    @patch('modules.booting.auditar_integridad_firmware', return_value={"mock": 1})
    @patch('modules.booting.auditar_parametros_kernel', return_value={"mock": 2})
    @patch('modules.booting.auditar_seguridad_grub', return_value={"mock": 3})
    def test_escaner_principal(self, mock_grub, mock_kernel, mock_firmware):
        # Comprobamos que el wrapper consolida los diccionarios correctamente
        res = ESCANER_booting(False, {"estado": "SEGURO"})
        self.assertEqual(res["integridad"]["mock"], 1)
        self.assertEqual(res["parametros"]["mock"], 2)
        self.assertEqual(res["grub"]["mock"], 3)

if __name__ == '__main__':
    unittest.main(verbosity=2)