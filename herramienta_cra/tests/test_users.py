# SealGuard - Herramienta de Auditoria CRA
# Copyright (C) 2026 Alvaro Sanchez Garijo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import modules.users as mUsers

# Falso settings.yaml para que los tests no dependan de tu archivo real
MOCK_CONFIG = {
    "users": {
        "critical_groups": ["root", "sudo"],
        "politics": ["PASS_MAX_DAYS", "UID_MIN"],
        "mfa": {
            "modulos_pam_2fa": ["pam_google_authenticator.so"],
            "servicios_pam_a_revisar": ["sshd", "sudo"],
            "parametros_ssh_requeridos": ["UsePAM yes", "ChallengeResponseAuthentication yes"],
            "tokens_requeridos": {".google_authenticator": "pam_google_authenticator.so"}
        }
    }
}

@patch.dict('modules.users.config', MOCK_CONFIG)
class TestUsuariosModulo(unittest.TestCase):

    # =========================================================================
    # 1. TESTS DE LA FUNCIÓN AUXILIAR: comprobar()
    # =========================================================================
    @patch('builtins.open', new_callable=mock_open, read_data="UsePAM yes\n#KbdInteractiveAuthentication yes\n")
    def test_comprobar_camino_feliz(self, mock_file):
        """Comprueba que encuentra texto y omite comentarios"""
        resultado = mUsers.comprobar("falso.txt", ["UsePAM yes", "KbdInteractiveAuthentication yes"])
        self.assertIn("UsePAM yes", resultado)
        self.assertNotIn("KbdInteractiveAuthentication yes", resultado) # Estaba comentado
        self.assertEqual(len(resultado), 1)

    @patch('builtins.open')
    def test_comprobar_camino_triste_no_existe(self, mock_file):
        """Comprueba que no peta si el archivo no existe (FileNotFound)"""
        mock_file.side_effect = FileNotFoundError()
        resultado = mUsers.comprobar("falso.txt", ["UsePAM yes"])
        self.assertEqual(resultado, []) # Debe devolver lista vacía en silencio

    @patch('builtins.open')
    def test_comprobar_camino_triste_sin_permisos(self, mock_file):
        """Comprueba manejo genérico de excepciones (PermissionError)"""
        mock_file.side_effect = PermissionError("Permiso denegado")
        resultado = mUsers.comprobar("falso.txt", ["UsePAM yes"])
        self.assertEqual(resultado, [])

    # =========================================================================
    # 2. TESTS DE: politicas_passwords()
    # =========================================================================
    @patch('builtins.open', new_callable=mock_open, read_data="PASS_MAX_DAYS 90\nUID_MIN 1000\n")
    def test_politicas_passwords_feliz(self, mock_file):
        """Extrae las políticas correctamente"""
        resultado = mUsers.politicas_passwords(verbose=False)
        self.assertEqual(resultado["PASS_MAX_DAYS"], "90")
        self.assertEqual(resultado["UID_MIN"], "1000")

    @patch('builtins.open')
    def test_politicas_passwords_excepciones(self, mock_file):
        """Prueba que el programa no colapse si login.defs falla"""
        # Prueba 1: Sin permisos
        mock_file.side_effect = PermissionError()
        res1 = mUsers.politicas_passwords(verbose=False)
        self.assertEqual(res1, {})

        # Prueba 2: No encontrado
        mock_file.side_effect = FileNotFoundError()
        res2 = mUsers.politicas_passwords(verbose=False)
        self.assertEqual(res2, {})

    # =========================================================================
    # 3. TESTS DE: juntar_datos()
    # =========================================================================
    def test_juntar_datos_camino_feliz(self):
        """Cruza los 3 sets de datos perfectamente"""
        usuarios = [{'username': 'user1', 'uid': '1000'}]
        grupos = [{'username': 'user1', 'groupname': 'sudo'}]
        shadow = [{'username': 'user1', 'max': '90'}]
        
        res = mUsers.juntar_datos(usuarios, grupos, shadow)
        self.assertEqual(res[0]['username'], 'user1')
        self.assertIn('sudo', res[0]['grupos_criticos'])
        self.assertEqual(res[0]['politica']['max'], '90')

    def test_juntar_datos_camino_triste_none(self):
        """Prueba de robustez: ¿Qué pasa si le pasamos listas vacías o None?"""
        res = mUsers.juntar_datos(None, None, None)
        self.assertEqual(res, []) # No debe petar con TypeError

    def test_juntar_datos_usuario_anomalo(self):
        """Detecta usuarios fantasma (en grupos pero no en el sistema)"""
        res = mUsers.juntar_datos([], [{'username': 'fantasma', 'groupname': 'root'}], [])
        self.assertEqual(res[0]['uid'], 'SISTEMA/ANÓMALO')

    # =========================================================================
    # 4. TESTS DE: info_usuarios_base()
    # =========================================================================
    @patch('modules.system.ejecutar_consulta')
    def test_info_usuarios_base_feliz(self, mock_sql):
        """Llamadas dinámicas SQL con datos existentes"""
        # Simulamos los 3 retornos de Osquery
        mock_sql.side_effect = [
            [{'username': 'admin', 'groupname': 'sudo'}],
            [{'username': 'admin', 'uid': '1000', 'shell': '/bin/bash'}],
            [{'username': 'admin', 'max': '90'}]
        ]
        res = mUsers.info_usuarios_base(verbose=False, uid_min=1000)
        self.assertEqual(mock_sql.call_count, 3)
        self.assertEqual(len(res), 1)

    @patch('modules.system.ejecutar_consulta')
    def test_info_usuarios_base_vacio(self, mock_sql):
        """Llamadas SQL sin resultados (para probar las cadenas de texto vacías en SQL)"""
        # Si no hay grupos críticos ni usuarios, no debe construir "IN ()" y fallar
        mock_sql.side_effect = [ [], [], [] ]
        res = mUsers.info_usuarios_base(verbose=False, uid_min=1000)
        self.assertEqual(res, [])

    # =========================================================================
    # 5. TESTS DE: comp_2FA()
    # =========================================================================
    @patch('modules.users.comprobar')
    @patch('os.path.exists')
    def test_comp_2FA_protegido_y_efectivo(self, mock_exists, mock_comprobar):
        """Camino feliz: MFA global, SSH válido y Token existe"""
        # Simulamos que comprobar() encuentra los módulos
        mock_comprobar.side_effect = [
            ['pam_google_authenticator.so'], # common-auth
            ['@include common-auth'],        # sshd
            ['@include common-auth'],        # sudo
            ['UsePAM yes', 'ChallengeResponseAuthentication yes'] # sshd_config
        ]
        # Simulamos que el archivo .google_authenticator existe
        mock_exists.return_value = True
        
        usuarios = [{'username': 'user1', 'directory': '/home/user1'}]
        res = mUsers.comp_2FA(verbose=False, usuarios=usuarios)
        
        self.assertTrue(res['mfa_global'])
        self.assertTrue(res['ssh_config_valido'])
        self.assertTrue(res['servicios']['sshd']['protegido'])
        self.assertEqual(res['usuarios_token'][0]['efectivo'], True)

    @patch('modules.users.comprobar')
    @patch('os.path.exists')
    def test_comp_2FA_camino_triste_falso_positivo(self, mock_exists, mock_comprobar):
        """Prueba de Seguridad: El token existe pero el PAM no está activo"""
        mock_comprobar.return_value = [] # PAM no tiene nada configurado
        mock_exists.return_value = True  # Pero el archivo .google_authenticator sí existe
        
        usuarios = [{'username': 'user1', 'directory': '/home/user1'}]
        res = mUsers.comp_2FA(verbose=False, usuarios=usuarios)
        
        self.assertFalse(res['mfa_global'])
        # La clave: El token se detecta, pero EFECTIVO debe ser False
        self.assertFalse(res['usuarios_token'][0]['efectivo'])

    def test_comp_2FA_directorios_invalidos(self):
        """Ignora cuentas de sistema sin home real"""
        usuarios = [{'username': 'nobody', 'directory': '/nonexistent'}]
        res = mUsers.comp_2FA(verbose=False, usuarios=usuarios)
        self.assertEqual(len(res['usuarios_token']), 0) # No debe buscar ahí

    # =========================================================================
    # 6. TESTS DE LA ORQUESTACIÓN: ESCANER_usuarios()
    # =========================================================================
    @patch('modules.users.comp_2FA')
    @patch('modules.users.info_usuarios_base')
    @patch('modules.users.politicas_passwords')
    def test_escaner_usuarios_flujo(self, mock_pol, mock_info, mock_2fa):
        """Comprueba que el orquestador encadena las funciones correctamente"""
        mock_pol.return_value = {"UID_MIN": "500"} # Simulamos RedHat
        mock_info.return_value = [{'user': 'test'}]
        mock_2fa.return_value = {'mfa_global': True}
        
        res = mUsers.ESCANER_usuarios(verbose=False)
        
        # Verificamos que se le pasó el UID 500 a la función base
        mock_info.assert_called_with(False, "500")
        self.assertTrue(res['2FA']['mfa_global'])

    @patch('modules.users.politicas_passwords')
    @patch('modules.users.info_usuarios_base')
    @patch('modules.users.comp_2FA')
    def test_escaner_usuarios_fallback_uid(self, mock_2fa, mock_info, mock_pol):
        """Comprueba el fallback si no hay UID_MIN"""
        mock_pol.return_value = {} # Sin UID
        
        mUsers.ESCANER_usuarios(verbose=False)
        
        # Verificamos que usó el 1000 por defecto
        mock_info.assert_called_with(False, 1000)

    @patch('modules.users.comprobar')
    @patch('os.path.exists')
    def test_comp_2FA_ssh_parcialmente_configurado(self, mock_exists, mock_comprobar):
        """Prueba de Seguridad: Falta el parámetro principal de PAM en SSH"""
        
        # Simulamos que existe el archivo sshd_config
        mock_exists.side_effect = lambda path: path == '/etc/ssh/sshd_config'
        
        # Simulamos que comprobar() devuelve la parte secundaria pero le falta 'UsePAM yes'
        mock_comprobar.side_effect = [
            [], # common-auth
            ['ChallengeResponseAuthentication yes', 'KbdInteractiveAuthentication yes'] # sshd_config
        ]
        
        # Le pasamos un usuario cualquiera para no fallar el bucle final
        usuarios = [{'username': 'user1', 'directory': '/home/user1'}]
        res = mUsers.comp_2FA(verbose=False, usuarios=usuarios)
        
        # La herramienta debe detectar que la configuración es inválida
        self.assertFalse(res['ssh_config_valido'])
        
if __name__ == '__main__':
    unittest.main(verbosity=2)