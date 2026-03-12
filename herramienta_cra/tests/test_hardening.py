import unittest
from unittest.mock import patch, mock_open, MagicMock

# Importamos apuntando a la carpeta modules
from modules.hardening import (
    auditar_suid_sgid, auditar_archivos_criticos, auditar_ssh,
    auditar_firewall, auditar_aslr, auditar_mac, 
    auditar_certificados, auditar_cifrado
)

# Constante estática para evitar el error del decorador en tiempo de carga de la clase
CERT_CONFIG_MOCK = {
    "hardening": {
        "certificados": {
            "dias_aviso_caducidad": 30, 
            "min_rsa_key_size": 2048, 
            "algoritmos_permitidos": ["sha256WithRSAEncryption"], 
            "rutas_criticas": [{"path": "/cert.pem", "tipo": "publico", "max_permissions": "644", "owner": "root"}]
        }
    }
}

class TestHardeningCompleto(unittest.TestCase):

    # =====================================================================
    # 1. TESTS: SUID / SGID (auditar_suid_sgid)
    # =====================================================================
    @patch('modules.hardening.config', {"hardening": {"suid_sgid": {"critical_directories": ["/tmp/"], "forviden_permissions": ["2", "3", "6", "7"]}}})
    @patch('modules.hardening.ejecutar_consulta')
    def test_suid_seguro(self, mock_db):
        mock_db.return_value = [{"path": "/usr/bin/sudo", "mode": "4755", "username": "root", "groupname": "root"}]
        res = auditar_suid_sgid(False)
        self.assertEqual(len(res["peligrosos"]), 0)

    @patch('modules.hardening.config', {"hardening": {"suid_sgid": {"critical_directories": ["/tmp/"], "forviden_permissions": ["2", "3", "6", "7"]}}})
    @patch('modules.hardening.ejecutar_consulta')
    def test_suid_peligro_directorio_parcial(self, mock_db):
        mock_db.return_value = [{"path": "/home/user/tmp/malware", "mode": "4755", "username": "hacker", "groupname": "hacker"}]
        res = auditar_suid_sgid(False)
        self.assertEqual(len(res["peligrosos"]), 1)

    @patch('modules.hardening.config', {"hardening": {"suid_sgid": {"critical_directories": ["/var/"], "forviden_permissions": ["2", "3", "6", "7"]}}})
    @patch('modules.hardening.ejecutar_consulta')
    def test_suid_peligro_permisos_aislados(self, mock_db):
        mock_db.return_value = [
            {"path": "/usr/bin/bad_group", "mode": "4775", "username": "root", "groupname": "root"},
            {"path": "/usr/bin/bad_others", "mode": "4757", "username": "root", "groupname": "root"}
        ]
        res = auditar_suid_sgid(False)
        self.assertEqual(len(res["peligrosos"]), 2)


    # =====================================================================
    # 2. TESTS: ARCHIVOS CRÍTICOS (auditar_archivos_criticos)
    # =====================================================================
    @patch('modules.hardening.config', {"hardening": {"critical_files": [{"path": "/etc/shadow", "max_permissions": "640", "owner": "root"}]}})
    @patch('modules.hardening.ejecutar_consulta')
    def test_archivos_criticos_perfecto(self, mock_db):
        mock_db.return_value = [{"path": "/etc/shadow", "mode": "0640", "username": "root"}]
        res = auditar_archivos_criticos(False)
        self.assertEqual(res[0]["estado"], "SEGURO")

    @patch('modules.hardening.config', {"hardening": {"critical_files": [{"path": "/etc/shadow", "max_permissions": "640", "owner": "root"}]}})
    @patch('modules.hardening.ejecutar_consulta')
    def test_archivos_criticos_excepcion_value_error(self, mock_db):
        mock_db.return_value = [{"path": "/etc/shadow", "mode": "texto_basura", "username": "root"}]
        res = auditar_archivos_criticos(False)
        self.assertEqual(res[0]["estado"], "PELIGROSO")
        self.assertTrue(any("Error al leer o convertir" in p for p in res[0]["problemas"]))


    # =====================================================================
    # 3. TESTS: SSH (auditar_ssh)
    # =====================================================================
    @patch('modules.hardening.config', {"hardening": {"ssh": {"secure_params": {"PermitRootLogin": "no", "MaxAuthTries": "4"}, "allowed_users": ["admin", "juan"]}}})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="PermitRootLogin no\nPort 2222\nAllowUsers admin juan\n")
    def test_ssh_parametro_ausente(self, mock_archivo, mock_exists):
        res = auditar_ssh(False)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertTrue(any("no está configurado en el servicio ssh" in a for a in res["alertas"]))

    @patch('modules.hardening.config', {"hardening": {"ssh": {"secure_params": {"PermitRootLogin": "no"}, "allowed_users": ["admin", "juan"]}}})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="PermitRootLogin no\nPort 2222\nAllowUsers admin pedro\n")
    def test_ssh_allowusers_desajustado(self, mock_archivo, mock_exists):
        res = auditar_ssh(False)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertTrue(any("no coincide" in a for a in res["alertas"]))


    # =====================================================================
    # 4. TESTS: FIREWALL (auditar_firewall)
    # =====================================================================
    @patch('modules.hardening.config', {"hardening": {"firewall_services": ["ufw.service"]}})
    @patch('modules.hardening.ejecutar_consulta')
    @patch('modules.hardening.subprocess.run')
    def test_firewall_seguro_iptables(self, mock_subproc, mock_db):
        mock_db.return_value = [{"id": "ufw.service", "active_state": "active", "unit_file_state": "enabled"}]
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP\n"
        mock_subproc.return_value = mock_proc
        
        res = auditar_firewall(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('modules.hardening.config', {"hardening": {"firewall_services": ["ufw.service"]}})
    @patch('modules.hardening.ejecutar_consulta')
    @patch('modules.hardening.subprocess.run')
    def test_firewall_fallback_nftables(self, mock_subproc, mock_db):
        mock_db.return_value = [{"id": "ufw.service", "active_state": "active", "unit_file_state": "enabled"}]
        
        def subprocess_side_effect(*args, **kwargs):
            comando = args[0]
            m = MagicMock()
            if comando[0] == 'iptables':
                m.returncode = 0
                m.stdout = "" 
            elif comando[0] == 'nft':
                m.returncode = 0
                m.stdout = "type filter hook input priority 0; policy drop;"
            return m
            
        mock_subproc.side_effect = subprocess_side_effect
        
        res = auditar_firewall(False)
        self.assertEqual(res["estado"], "SEGURO")
        self.assertNotIn("no existen reglas de bloqueo", res["alertas"])


    # =====================================================================
    # 5. TESTS: ASLR (auditar_aslr)
    # =====================================================================
    @patch('modules.hardening.ejecutar_consulta', return_value=[{"current_value": "2"}])
    def test_aslr_seguro(self, mock_db):
        res = auditar_aslr(False)
        self.assertEqual(res["estado"], "SEGURO")


    # =====================================================================
    # 6. TESTS: MAC (auditar_mac)
    # =====================================================================
    @patch('modules.hardening.ejecutar_consulta')
    def test_mac_selinux_enforcing(self, mock_db):
        def side_effect(query):
            if 'selinux/config' in query: return [{"path": "/etc"}]
            if 'selinux_settings' in query: return [{"value": "1"}]
            return []
        mock_db.side_effect = side_effect
        
        res = auditar_mac(False)
        self.assertEqual(res["estado"], "SEGURO")
        self.assertEqual(res["mac_activo"], "SELinux")


    # =====================================================================
    # 7. TESTS: CERTIFICADOS (auditar_certificados)
    # =====================================================================
    @patch('modules.hardening.config', CERT_CONFIG_MOCK)
    @patch('os.path.exists', return_value=True)
    @patch('os.stat')
    @patch('pwd.getpwuid')
    @patch('modules.hardening.ejecutar_consulta')
    @patch('modules.hardening.subprocess.run')
    @patch('time.time', return_value=0)
    def test_certificados_perfecto(self, mock_time, mock_subproc, mock_db, mock_pwd, mock_stat, mock_exists):
        mock_stat.return_value.st_mode = 0o100644
        mock_pwd.return_value.pw_name = "root"
        mock_db.return_value = [{"not_valid_after": "10000000", "signing_algorithm": "sha256WithRSAEncryption", "issuer": "CA", "subject": "Web"}]
        
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Public-Key: (2048 bit)\nTLS Web Server Authentication"
        mock_subproc.return_value = mock_proc
        
        res = auditar_certificados(False)
        self.assertEqual(res["estado"], "SEGURO")


    # =====================================================================
    # 8. TESTS: CIFRADO (auditar_cifrado)
    # =====================================================================
    @patch('modules.hardening.config', {"hardening": {"encryption": {"algoritmo": "aes", "critical_mounts": ["/", "/var"]}}})
    @patch('modules.hardening.ejecutar_consulta')
    @patch('modules.hardening.subprocess.run')
    def test_cifrado_todo_seguro(self, mock_subproc, mock_db):
        mock_db.return_value = [
            {"device_alias": "root", "path": "/", "encrypted": "1"},
            {"device_alias": "var", "path": "/var", "encryption_status": "encrypted"}
        ]
        mock_subproc.return_value.returncode = 0
        mock_subproc.return_value.stdout = "cipher: aes-xts"
        
        res = auditar_cifrado(False)
        self.assertEqual(res["estado"], "SEGURO")

if __name__ == '__main__':
    unittest.main(verbosity=2)