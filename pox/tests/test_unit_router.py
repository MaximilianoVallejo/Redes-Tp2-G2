import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# --- Ajuste de Rutas (Pathing) ---
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
POX_BASE_DIR = os.path.dirname(TEST_DIR) 

sys.path.append(POX_BASE_DIR)
sys.path.append(os.path.join(POX_BASE_DIR, 'ext'))

try:
    from pox.lib.addresses import IPAddr, EthAddr
    import protorouter
except ImportError as e:
    print(f"[ERROR] No se pudieron cargar los módulos: {e}")
    sys.exit(1)


class TestProtoRouterARP(unittest.TestCase):

    # MOCKEAMOS EL TIMER: Evita que POX intente iniciar el reloj durante los tests
    @patch('protorouter.Timer')
    def setUp(self, mock_timer):
        self.mock_connection = MagicMock()
        self.router = protorouter.ProtoRouter(self.mock_connection)
        
        self.ip_privada = IPAddr("192.168.1.10")
        self.mac_privada = EthAddr("00:00:00:00:00:10")
        self.puerto_privado = 2
        
        self.ip_publica = IPAddr("192.168.2.1")
        self.mac_publica = EthAddr("00:00:00:00:00:aa")
        self.puerto_publico = 1

    def test_arp_learning_and_resolution(self):
        # Estado inicial: guardamos en una sola variable para evitar el crash si es None
        resultado_inicial = self.router.resolve_mac(self.ip_privada)
        self.assertIsNone(resultado_inicial, "La tabla ARP debería estar vacía inicialmente.")
        
        # Acto: El router aprende dinámicamente
        self.router.learn(self.ip_privada, self.mac_privada, self.puerto_privado)
        
        # Validación: Ahora resolve_mac devuelve una tupla, así que podemos desempaquetar
        resolved_mac, resolved_port = self.router.resolve_mac(self.ip_privada)
        
        self.assertEqual(resolved_mac, self.mac_privada)
        self.assertEqual(resolved_port, self.puerto_privado)

    def test_queue_pending_packets(self):
        mock_event = MagicMock()
        mock_event.port = self.puerto_privado
        
        self.assertNotIn(self.ip_publica, self.router.pending)
        
        self.router.queue_pending(self.ip_publica, mock_event)
        self.assertIn(self.ip_publica, self.router.pending)
        
        # CORRECCIÓN: Medimos y verificamos específicamente la lista "events"
        self.assertEqual(len(self.router.pending[self.ip_publica]["events"]), 1)
        self.assertEqual(self.router.pending[self.ip_publica]["events"][0], mock_event)

    def test_resolve_pending_empties_queue(self):
        mock_event = MagicMock()
        self.router.queue_pending(self.ip_publica, mock_event)
        self.router.learn(self.ip_publica, self.mac_publica, self.puerto_publico)
        
        with patch.object(self.router, 'handle_ip') as mock_handle_ip:
            self.router.resolve_pending(self.ip_publica)
            mock_handle_ip.assert_called_once_with(mock_event)
            
        self.assertNotIn(self.ip_publica, self.router.pending)


if __name__ == '__main__':
    unittest.main()