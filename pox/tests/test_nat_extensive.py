"""
Tests extensivos para protorouter.py (TP2 - SDN NAT).

Cubren:
  - Manejo de ARP (resolución dinámica, cola de pendientes, reintentos)
  - NAT por puertos / PAT (asignación, reuso, múltiples clientes, TCP/UDP)
  - Instalación de flujos OpenFlow (saliente / entrante, matches y acciones)
  - Liberación de recursos al expirar un flujo (FlowRemoved)
  - Camino completo: paquete real (Ethernet+IP+TCP/UDP) entrando al
    controlador, sin mockear la lógica de negocio, solo connection.send().

No requieren Mininet ni un controlador POX corriendo: se instancia
ProtoRouter directamente con una conexión mockeada, igual que en
test_unit_router.py.

Ejecutar:
    cd pox
    python3 -m pytest tests/test_nat_extensive.py -v
    # o sin pytest:
    python3 tests/test_nat_extensive.py
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
POX_BASE_DIR = os.path.dirname(TEST_DIR)
sys.path.append(POX_BASE_DIR)
sys.path.append(os.path.join(POX_BASE_DIR, 'ext'))

try:
    from pox.lib.addresses import IPAddr, EthAddr
    from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
    from pox.lib.packet.ipv4 import ipv4
    from pox.lib.packet.tcp import tcp
    from pox.lib.packet.udp import udp
    from pox.lib.packet.arp import arp
    import pox.openflow.libopenflow_01 as of
    import protorouter
except ImportError as e:
    print(f"[ERROR] No se pudieron cargar los módulos: {e}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers de construcción de paquetes (réplica de lo que envía un host real)
# ---------------------------------------------------------------------------

def build_tcp_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                      flags=0x02, seq=1000, ack=0):
    """Construye y "parsea" un frame Ethernet con TCP adentro, igual a como
    llegaría desde Mininet vía OpenFlow PacketIn."""
    t = tcp()
    t.srcport = src_port
    t.dstport = dst_port
    t.seq = seq
    t.ack = ack
    t.off = 5
    t.flags = flags
    t.win = 8192

    ip = ipv4()
    ip.protocol = ipv4.TCP_PROTOCOL
    ip.srcip = src_ip
    ip.dstip = dst_ip
    ip.payload = t

    eth = ethernet()
    eth.type = ethernet.IP_TYPE
    eth.src = src_mac
    eth.dst = dst_mac
    eth.payload = ip

    return ethernet(raw=eth.pack())  # ida y vuelta por pack/parse, como en la red real


def build_udp_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload=b"hola"):
    u = udp()
    u.srcport = src_port
    u.dstport = dst_port
    u.payload = payload

    ip = ipv4()
    ip.protocol = ipv4.UDP_PROTOCOL
    ip.srcip = src_ip
    ip.dstip = dst_ip
    ip.payload = u

    eth = ethernet()
    eth.type = ethernet.IP_TYPE
    eth.src = src_mac
    eth.dst = dst_mac
    eth.payload = ip

    return ethernet(raw=eth.pack())


def build_arp_request(src_mac, src_ip, dst_ip):
    a = arp()
    a.opcode = arp.REQUEST
    a.hwsrc = src_mac
    a.hwdst = ETHER_BROADCAST
    a.protosrc = src_ip
    a.protodst = dst_ip

    eth = ethernet()
    eth.type = ethernet.ARP_TYPE
    eth.src = src_mac
    eth.dst = ETHER_BROADCAST
    eth.payload = a
    return ethernet(raw=eth.pack())


def build_arp_reply(src_mac, src_ip, dst_mac, dst_ip):
    a = arp()
    a.opcode = arp.REPLY
    a.hwsrc = src_mac
    a.hwdst = dst_mac
    a.protosrc = src_ip
    a.protodst = dst_ip

    eth = ethernet()
    eth.type = ethernet.ARP_TYPE
    eth.src = src_mac
    eth.dst = dst_mac
    eth.payload = a
    return ethernet(raw=eth.pack())


def make_event(parsed_packet, in_port):
    event = MagicMock()
    event.parsed = parsed_packet
    event.port = in_port
    return event


def sent_flow_mods(mock_connection):
    """Devuelve todos los ofp_flow_mod enviados por connection.send(...)."""
    return [c.args[0] for c in mock_connection.send.call_args_list
            if isinstance(c.args[0], of.ofp_flow_mod)]


def sent_packet_outs(mock_connection):
    return [c.args[0] for c in mock_connection.send.call_args_list
            if isinstance(c.args[0], of.ofp_packet_out)]


def flow_mod_action(fm, action_type):
    for a in fm.actions:
        if isinstance(a, action_type):
            return a
    return None


# ---------------------------------------------------------------------------
# Setup común
# ---------------------------------------------------------------------------

class BaseRouterTest(unittest.TestCase):

    @patch('protorouter.Timer')
    def setUp(self, mock_timer):
        self.mock_connection = MagicMock()
        self.router = protorouter.ProtoRouter(self.mock_connection)

        # Direcciones del NAT (deben matchear protorouter.py)
        self.PUBLIC_IP = protorouter.PUBLIC_IP
        self.PUBLIC_MAC = protorouter.PUBLIC_MAC
        self.PRIVATE_IP = protorouter.PRIVATE_IP
        self.PRIVATE_MAC = protorouter.PRIVATE_MAC
        self.PUBLIC_PORT = protorouter.PUBLIC_PORT

        # Host público (servidor, ej. h1)
        self.server_ip = IPAddr("200.0.0.1")
        self.server_mac = EthAddr("00:00:00:00:00:01")

        # Hosts privados (ej. h2, h3, h4)
        self.h2_ip, self.h2_mac, self.h2_port = IPAddr("192.168.1.2"), EthAddr("00:00:00:00:00:02"), 2
        self.h3_ip, self.h3_mac, self.h3_port = IPAddr("192.168.1.3"), EthAddr("00:00:00:00:00:03"), 3
        self.h4_ip, self.h4_mac, self.h4_port = IPAddr("192.168.1.4"), EthAddr("00:00:00:00:00:04"), 4

        # Pre-cargamos la tabla ARP para los tests que no son sobre ARP en sí,
        # simulando que ya hubo un intercambio ARP previo.
        self.router.learn(self.server_ip, self.server_mac, self.PUBLIC_PORT)
        self.router.learn(self.h2_ip, self.h2_mac, self.h2_port)
        self.router.learn(self.h3_ip, self.h3_mac, self.h3_port)
        self.router.learn(self.h4_ip, self.h4_mac, self.h4_port)


# ===========================================================================
# 1. ARP: resolución dinámica
# ===========================================================================

class TestArpResolution(BaseRouterTest):

    def test_no_static_arp_entries_on_init(self):
        """La tabla ARP debe nacer vacía: nada hardcodeado."""
        fresh = protorouter.ProtoRouter.__new__(protorouter.ProtoRouter)
        with patch('protorouter.Timer'):
            fresh.__init__(MagicMock())
        self.assertEqual(fresh.arp_table, {})
        self.assertEqual(fresh.pending, {})

    def test_router_replies_to_arp_for_public_ip_on_public_port(self):
        req = build_arp_request(self.server_mac, self.server_ip, self.PUBLIC_IP)
        event = make_event(req, self.PUBLIC_PORT)
        self.router.handle_arp(event)

        pkt_outs = sent_packet_outs(self.mock_connection)
        self.assertEqual(len(pkt_outs), 1, "Debe responder con exactamente un ARP Reply")

        reply_eth = ethernet(raw=pkt_outs[0].data)
        self.assertEqual(reply_eth.type, ethernet.ARP_TYPE)
        reply_arp = reply_eth.payload
        self.assertEqual(reply_arp.opcode, arp.REPLY)
        self.assertEqual(reply_arp.hwsrc, self.PUBLIC_MAC)
        self.assertEqual(reply_arp.protosrc, self.PUBLIC_IP)
        self.assertEqual(reply_arp.hwdst, self.server_mac)

    def test_router_replies_to_arp_for_private_ip_on_private_port(self):
        req = build_arp_request(self.h2_mac, self.h2_ip, self.PRIVATE_IP)
        event = make_event(req, self.h2_port)
        self.router.handle_arp(event)

        pkt_outs = sent_packet_outs(self.mock_connection)
        self.assertEqual(len(pkt_outs), 1)
        reply_arp = ethernet(raw=pkt_outs[0].data).payload
        self.assertEqual(reply_arp.hwsrc, self.PRIVATE_MAC)
        self.assertEqual(reply_arp.protosrc, self.PRIVATE_IP)

    def test_router_ignores_arp_for_foreign_ip(self):
        """No debe contestar por una IP que no es propia (ni pública ni privada)."""
        req = build_arp_request(self.h2_mac, self.h2_ip, IPAddr("192.168.1.99"))
        event = make_event(req, self.h2_port)
        self.router.handle_arp(event)
        self.assertEqual(len(sent_packet_outs(self.mock_connection)), 0)

    def test_router_ignores_arp_for_public_ip_seen_on_private_port(self):
        """Anti-spoofing básico: la IP pública del NAT solo se contesta si la
        pregunta entra por PUBLIC_PORT."""
        req = build_arp_request(self.h2_mac, self.h2_ip, self.PUBLIC_IP)
        event = make_event(req, self.h2_port)
        self.router.handle_arp(event)
        self.assertEqual(len(sent_packet_outs(self.mock_connection)), 0)

    def test_arp_reply_updates_table(self):
        fresh_ip = IPAddr("200.0.0.50")
        fresh_mac = EthAddr("00:00:00:00:00:50")
        self.assertIsNone(self.router.resolve_mac(fresh_ip))

        reply = build_arp_reply(fresh_mac, fresh_ip, self.PUBLIC_MAC, self.PUBLIC_IP)
        event = make_event(reply, self.PUBLIC_PORT)
        self.router.handle_arp(event)

        resolved = self.router.resolve_mac(fresh_ip)
        self.assertEqual(resolved, (fresh_mac, self.PUBLIC_PORT))

    def test_arp_probe_with_src_0_0_0_0_not_learned(self):
        """Un ARP probe (gratuitous, src 0.0.0.0) no debe contaminar la tabla."""
        req = build_arp_request(self.h2_mac, IPAddr("0.0.0.0"), self.PRIVATE_IP)
        event = make_event(req, self.h2_port)
        self.router.handle_arp(event)
        self.assertIsNone(self.router.resolve_mac(IPAddr("0.0.0.0")))


# ===========================================================================
# 2. ARP: cola de pendientes y reintentos
# ===========================================================================

class TestArpPendingQueue(BaseRouterTest):

    def test_unknown_destination_triggers_single_arp_request_and_queues_packet(self):
        unknown_ip = IPAddr("200.0.0.77")
        pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, unknown_ip, 40000, 80)
        event = make_event(pkt, self.h2_port)

        self.router.handle_ip(event)

        # No debe haber instalado flujos todavía (falta resolver MAC)
        self.assertEqual(len(sent_flow_mods(self.mock_connection)), 0)
        self.assertIn(unknown_ip, self.router.pending)
        self.assertEqual(len(self.router.pending[unknown_ip]["events"]), 1)

        # Debe haber emitido exactamente un ARP request
        arp_pkt_outs = [
            ethernet(raw=po.data) for po in sent_packet_outs(self.mock_connection)
        ]
        arps = [e for e in arp_pkt_outs if e.type == ethernet.ARP_TYPE]
        self.assertEqual(len(arps), 1)
        self.assertEqual(arps[0].payload.protodst, unknown_ip)

    def test_second_packet_to_same_unresolved_ip_does_not_resend_arp(self):
        unknown_ip = IPAddr("200.0.0.77")
        pkt1 = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, unknown_ip, 40000, 80)
        pkt2 = build_tcp_packet(self.h3_mac, self.PRIVATE_MAC, self.h3_ip, unknown_ip, 40001, 80)

        self.router.handle_ip(make_event(pkt1, self.h2_port))
        self.router.handle_ip(make_event(pkt2, self.h3_port))

        self.assertEqual(len(self.router.pending[unknown_ip]["events"]), 2)
        arp_outs = [ethernet(raw=po.data) for po in sent_packet_outs(self.mock_connection)
                    if ethernet(raw=po.data).type == ethernet.ARP_TYPE]
        self.assertEqual(len(arp_outs), 1, "No debe reenviar un ARP Request si ya hay uno en vuelo")

    def test_arp_resolution_flushes_all_pending_packets(self):
        unknown_ip = IPAddr("200.0.0.77")
        pkt1 = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, unknown_ip, 40000, 80)
        pkt2 = build_tcp_packet(self.h3_mac, self.PRIVATE_MAC, self.h3_ip, unknown_ip, 40001, 80)
        self.router.handle_ip(make_event(pkt1, self.h2_port))
        self.router.handle_ip(make_event(pkt2, self.h3_port))

        self.mock_connection.reset_mock()

        reply_mac = EthAddr("00:00:00:00:00:77")
        reply = build_arp_reply(reply_mac, unknown_ip, self.PUBLIC_MAC, self.PUBLIC_IP)
        self.router.handle_arp(make_event(reply, self.PUBLIC_PORT))

        self.assertNotIn(unknown_ip, self.router.pending)
        # Ambos paquetes reprocesados -> 2 conexiones NAT distintas -> 2 flujos salientes
        flow_mods = sent_flow_mods(self.mock_connection)
        outgoing_flows = [fm for fm in flow_mods if fm.match.in_port in (self.h2_port, self.h3_port)]
        self.assertEqual(len(outgoing_flows), 2)

    def test_retry_then_drop_after_max_retries(self):
        unknown_ip = IPAddr("200.0.0.88")
        pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, unknown_ip, 40000, 80)
        self.router.handle_ip(make_event(pkt, self.h2_port))
        self.assertIn(unknown_ip, self.router.pending)
        self.assertEqual(self.router.pending[unknown_ip]["retries"], 1)

        # Reintentos manuales (simulan al Timer disparando _retry_pending_arps)
        for _ in range(protorouter.ARP_MAX_RETRIES - 1):
            self.router._retry_pending_arps()
        self.assertIn(unknown_ip, self.router.pending)
        self.assertEqual(self.router.pending[unknown_ip]["retries"], protorouter.ARP_MAX_RETRIES)

        # Un reintento más supera el máximo -> se descarta
        self.router._retry_pending_arps()
        self.assertNotIn(unknown_ip, self.router.pending)


# ===========================================================================
# 3. NAT / PAT: asignación y reuso de puertos públicos
# ===========================================================================

class TestNatPortAssignment(BaseRouterTest):

    def test_new_connection_gets_a_public_port_in_range(self):
        pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        self.router.handle_outgoing(make_event(pkt, self.h2_port))

        self.assertEqual(len(self.router.nat_table), 1)
        pub_port = list(self.router.nat_table.values())[0]
        self.assertTrue(protorouter.NAT_PORT_START <= pub_port <= protorouter.NAT_PORT_END)

    def test_retransmission_of_same_flow_reuses_same_public_port(self):
        pkt1 = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80, seq=1000)
        pkt2 = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80, seq=1000)

        self.router.handle_outgoing(make_event(pkt1, self.h2_port))
        port_1 = list(self.router.nat_table.values())[0]

        self.router.handle_outgoing(make_event(pkt2, self.h2_port))
        self.assertEqual(len(self.router.nat_table), 1, "No debe crear una segunda entrada para el mismo 5-tuple")
        port_2 = list(self.router.nat_table.values())[0]
        self.assertEqual(port_1, port_2)

    def test_same_host_different_destinations_get_different_ports(self):
        other_server_ip = IPAddr("200.0.0.2")
        other_server_mac = EthAddr("00:00:00:00:00:09")
        # La MAC del segundo destino debe conocerse de antemano (vía ARP),
        # igual que server_ip ya fue precargada en setUp.
        self.router.learn(other_server_ip, other_server_mac, self.PUBLIC_PORT)

        pkt1 = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        pkt2 = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, other_server_ip, 40000, 80)

        self.router.handle_outgoing(make_event(pkt1, self.h2_port))
        self.router.handle_outgoing(make_event(pkt2, self.h2_port))

        self.assertEqual(len(self.router.nat_table), 2)
        ports = list(self.router.nat_table.values())
        self.assertEqual(len(set(ports)), 2, "Distintos destinos -> distintos puertos públicos")

    def test_multiple_clients_simultaneous_get_distinct_ports(self):
        """h2, h3 y h4 hablando con el mismo servidor al mismo tiempo:
        cada conexión debe tener su propio puerto público."""
        pkt_h2 = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 5001)
        pkt_h3 = build_tcp_packet(self.h3_mac, self.PRIVATE_MAC, self.h3_ip, self.server_ip, 40000, 5001)
        pkt_h4 = build_tcp_packet(self.h4_mac, self.PRIVATE_MAC, self.h4_ip, self.server_ip, 40000, 5001)

        self.router.handle_outgoing(make_event(pkt_h2, self.h2_port))
        self.router.handle_outgoing(make_event(pkt_h3, self.h3_port))
        self.router.handle_outgoing(make_event(pkt_h4, self.h4_port))

        self.assertEqual(len(self.router.nat_table), 3)
        ports = list(self.router.nat_table.values())
        self.assertEqual(len(set(ports)), 3, "Mismo IP/puerto origen en 3 hosts distintos -> 3 puertos públicos distintos")

        # Cada entrada debe mapear de vuelta al host privado correcto
        for pub_port, priv_ip in [(ports[0], None)]:
            pass  # placeholder, validado en detalle en TestIncomingTranslation

    def test_tcp_and_udp_from_same_host_port_get_separate_nat_entries(self):
        tcp_pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        udp_pkt = build_udp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 53)

        self.router.handle_outgoing(make_event(tcp_pkt, self.h2_port))
        self.router.handle_outgoing(make_event(udp_pkt, self.h2_port))

        self.assertEqual(len(self.router.nat_table), 2, "TCP y UDP con mismo puerto deben ser entradas NAT separadas")

    def test_ports_are_released_and_reused(self):
        pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        self.router.handle_outgoing(make_event(pkt, self.h2_port))
        pub_port = list(self.router.nat_table.values())[0]

        self.assertNotIn(pub_port, self.router.available_ports)
        self.router.release_public_port(pub_port)
        self.assertIn(pub_port, self.router.available_ports)
        self.assertEqual(len(self.router.nat_table), 0)
        self.assertEqual(len(self.router.used_ports), 0)

    def test_pool_exhaustion_drops_packet_gracefully(self):
        """Si no hay puertos disponibles, el controlador no debe crashear:
        debe loguear y descartar el paquete."""
        self.router.available_ports = set()  # agotamos el pool
        pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        try:
            self.router.handle_outgoing(make_event(pkt, self.h2_port))
        except Exception as e:
            self.fail(f"handle_outgoing no debe lanzar excepción con pool agotado: {e}")
        self.assertEqual(len(self.router.nat_table), 0)
        self.assertEqual(len(sent_flow_mods(self.mock_connection)), 0)


# ===========================================================================
# 4. NAT / PAT: traducción del paquete y de la conexión de vuelta
# ===========================================================================

class TestOutgoingTranslation(BaseRouterTest):

    def test_outgoing_packet_out_has_translated_src_ip_and_port(self):
        pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        self.router.handle_outgoing(make_event(pkt, self.h2_port))

        pkt_outs = sent_packet_outs(self.mock_connection)
        self.assertEqual(len(pkt_outs), 1)
        sent_eth = ethernet(raw=pkt_outs[0].data)
        sent_ip = sent_eth.payload
        sent_tcp = sent_ip.payload

        pub_port = list(self.router.nat_table.values())[0]
        self.assertEqual(sent_ip.srcip, self.PUBLIC_IP)
        self.assertEqual(sent_tcp.srcport, pub_port)
        self.assertEqual(sent_eth.src, self.PUBLIC_MAC)
        self.assertEqual(sent_eth.dst, self.server_mac)
        # El destino (servidor) no debe alterarse
        self.assertEqual(sent_ip.dstip, self.server_ip)
        self.assertEqual(sent_tcp.dstport, 80)


class TestIncomingTranslation(BaseRouterTest):

    def _open_connection(self, priv_host_mac, priv_ip, priv_port_switch, src_port=40000, dst_port=80):
        """Simula el SYN saliente para crear la entrada NAT, y devuelve el
        puerto público asignado."""
        pkt = build_tcp_packet(priv_host_mac, self.PRIVATE_MAC, priv_ip, self.server_ip, src_port, dst_port)
        self.router.handle_outgoing(make_event(pkt, priv_port_switch))
        return list(self.router.nat_table.values())[-1]

    def test_incoming_reply_is_detranslated_to_correct_private_host(self):
        pub_port = self._open_connection(self.h3_mac, self.h3_ip, self.h3_port)
        self.mock_connection.reset_mock()

        # SYN-ACK del servidor hacia la IP/puerto públicos
        reply = build_tcp_packet(self.server_mac, self.PUBLIC_MAC, self.server_ip,
                                  self.PUBLIC_IP, 80, pub_port, flags=0x12)
        self.router.handle_incoming(make_event(reply, self.PUBLIC_PORT))

        pkt_outs = sent_packet_outs(self.mock_connection)
        self.assertEqual(len(pkt_outs), 1)
        sent_eth = ethernet(raw=pkt_outs[0].data)
        sent_ip = sent_eth.payload
        sent_tcp = sent_ip.payload

        self.assertEqual(sent_ip.dstip, self.h3_ip, "Debe dirigirse al host privado correcto (h3, no otro)")
        self.assertEqual(sent_tcp.dstport, 40000)
        self.assertEqual(sent_eth.dst, self.h3_mac)
        self.assertEqual(sent_eth.src, self.PRIVATE_MAC)

    def test_incoming_packet_to_unknown_public_port_is_dropped(self):
        unused_port = 10999
        reply = build_tcp_packet(self.server_mac, self.PUBLIC_MAC, self.server_ip,
                                  self.PUBLIC_IP, 80, unused_port)
        self.router.handle_incoming(make_event(reply, self.PUBLIC_PORT))
        self.assertEqual(len(sent_packet_outs(self.mock_connection)), 0)
        self.assertEqual(len(sent_flow_mods(self.mock_connection)), 0)

    def test_three_concurrent_clients_each_get_correct_reply_routing(self):
        """Reproduce el escenario de la demo: h2, h3 y h4 con conexiones
        simultáneas al mismo servidor; cada respuesta debe volver al host
        privado correcto según el puerto público que le tocó."""
        port_h2 = self._open_connection(self.h2_mac, self.h2_ip, self.h2_port, src_port=50000)
        port_h3 = self._open_connection(self.h3_mac, self.h3_ip, self.h3_port, src_port=50000)
        port_h4 = self._open_connection(self.h4_mac, self.h4_ip, self.h4_port, src_port=50000)

        self.assertEqual(len({port_h2, port_h3, port_h4}), 3)

        for pub_port, expected_ip, expected_mac in [
            (port_h2, self.h2_ip, self.h2_mac),
            (port_h3, self.h3_ip, self.h3_mac),
            (port_h4, self.h4_ip, self.h4_mac),
        ]:
            self.mock_connection.reset_mock()
            reply = build_tcp_packet(self.server_mac, self.PUBLIC_MAC, self.server_ip,
                                      self.PUBLIC_IP, 80, pub_port)
            self.router.handle_incoming(make_event(reply, self.PUBLIC_PORT))
            sent_eth = ethernet(raw=sent_packet_outs(self.mock_connection)[0].data)
            self.assertEqual(sent_eth.payload.dstip, expected_ip)
            self.assertEqual(sent_eth.dst, expected_mac)

    def test_incoming_with_arp_pending_is_queued_not_dropped(self):
        """Si la entrada NAT existe pero todavía no se conoce la MAC del
        host privado (caso raro, pero contemplado), el paquete se encola
        en vez de descartarse."""
        pub_port = self._open_connection(self.h2_mac, self.h2_ip, self.h2_port)
        # Olvidamos la MAC de h2 a propósito
        del self.router.arp_table[self.h2_ip]

        reply = build_tcp_packet(self.server_mac, self.PUBLIC_MAC, self.server_ip,
                                  self.PUBLIC_IP, 80, pub_port)
        event = make_event(reply, self.PUBLIC_PORT)
        self.router.handle_incoming(event)

        self.assertIn(self.h2_ip, self.router.pending)
        self.assertEqual(self.router.pending[self.h2_ip]["events"][0], event)


# ===========================================================================
# 5. Instalación de flujos OpenFlow: matches y acciones correctos
# ===========================================================================

class TestFlowInstallation(BaseRouterTest):

    def test_outgoing_flow_match_and_actions(self):
        pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        self.router.handle_outgoing(make_event(pkt, self.h2_port))
        pub_port = list(self.router.nat_table.values())[0]

        flow_mods = sent_flow_mods(self.mock_connection)
        out_fm = next(fm for fm in flow_mods if fm.match.in_port == self.h2_port)

        m = out_fm.match
        self.assertEqual(m.dl_type, 0x800)
        self.assertEqual(m.nw_proto, protorouter.PROTO_TCP)
        self.assertEqual(m.nw_src, self.h2_ip)
        self.assertEqual(m.nw_dst, self.server_ip)
        self.assertEqual(m.tp_src, 40000)
        self.assertEqual(m.tp_dst, 80)

        nw_src_action = flow_mod_action(out_fm, of.ofp_action_nw_addr)
        self.assertEqual(nw_src_action.nw_addr, self.PUBLIC_IP)
        tp_src_action = flow_mod_action(out_fm, of.ofp_action_tp_port)
        self.assertEqual(tp_src_action.tp_port, pub_port)

        self.assertTrue(out_fm.flags & of.OFPFF_SEND_FLOW_REM,
                         "El flujo saliente debe pedir notificación de expiración")
        self.assertEqual(out_fm.idle_timeout, protorouter.TCP_TIMEOUT)

    def test_incoming_flow_match_and_actions(self):
        pkt = build_tcp_packet(self.h3_mac, self.PRIVATE_MAC, self.h3_ip, self.server_ip, 40000, 80)
        self.router.handle_outgoing(make_event(pkt, self.h3_port))
        pub_port = list(self.router.nat_table.values())[0]
        self.mock_connection.reset_mock()

        reply = build_tcp_packet(self.server_mac, self.PUBLIC_MAC, self.server_ip,
                                  self.PUBLIC_IP, 80, pub_port)
        self.router.handle_incoming(make_event(reply, self.PUBLIC_PORT))

        flow_mods = sent_flow_mods(self.mock_connection)
        in_fm = next(fm for fm in flow_mods if fm.match.in_port == self.PUBLIC_PORT)

        m = in_fm.match
        self.assertEqual(m.nw_src, self.server_ip)
        self.assertEqual(m.nw_dst, self.PUBLIC_IP)
        self.assertEqual(m.tp_dst, pub_port)

        nw_dst_action = flow_mod_action(in_fm, of.ofp_action_nw_addr)
        self.assertEqual(nw_dst_action.nw_addr, self.h3_ip)
        tp_dst_action = flow_mod_action(in_fm, of.ofp_action_tp_port)
        self.assertEqual(tp_dst_action.tp_port, 40000)

        self.assertFalse(in_fm.flags & of.OFPFF_SEND_FLOW_REM,
                          "El flujo entrante no debe ser el dueño del timeout (lo es el saliente)")

    def test_udp_flows_use_udp_timeout(self):
        pkt = build_udp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 53)
        self.router.handle_outgoing(make_event(pkt, self.h2_port))
        flow_mods = sent_flow_mods(self.mock_connection)
        out_fm = next(fm for fm in flow_mods if fm.match.in_port == self.h2_port)
        self.assertEqual(out_fm.idle_timeout, protorouter.UDP_TIMEOUT)
        self.assertEqual(out_fm.match.nw_proto, protorouter.PROTO_UDP)


# ===========================================================================
# 6. Expiración de flujos: liberación de recursos (FlowRemoved)
# ===========================================================================

class TestFlowExpiration(BaseRouterTest):

    def test_flow_removed_releases_public_port(self):
        pkt = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        self.router.handle_outgoing(make_event(pkt, self.h2_port))
        pub_port = list(self.router.nat_table.values())[0]
        self.assertNotIn(pub_port, self.router.available_ports)

        removed_event = MagicMock()
        removed_event.ofp.match.nw_proto = protorouter.PROTO_TCP
        removed_event.ofp.match.nw_src = self.h2_ip
        removed_event.ofp.match.tp_src = 40000
        removed_event.ofp.match.nw_dst = self.server_ip
        removed_event.ofp.match.tp_dst = 80

        self.router._handle_FlowRemoved(removed_event)

        self.assertIn(pub_port, self.router.available_ports)
        self.assertEqual(len(self.router.nat_table), 0)
        self.assertEqual(len(self.router.used_ports), 0)

    def test_flow_removed_for_unknown_flow_is_noop(self):
        """No debe crashear ni tocar el estado si llega un FlowRemoved que
        no corresponde a ninguna conexión NAT activa."""
        removed_event = MagicMock()
        removed_event.ofp.match.nw_proto = protorouter.PROTO_TCP
        removed_event.ofp.match.nw_src = IPAddr("192.168.1.50")
        removed_event.ofp.match.tp_src = 12345
        removed_event.ofp.match.nw_dst = IPAddr("8.8.8.8")
        removed_event.ofp.match.tp_dst = 443
        try:
            self.router._handle_FlowRemoved(removed_event)
        except Exception as e:
            self.fail(f"No debe lanzar excepción ante flujo desconocido: {e}")

    def test_released_port_can_be_reassigned_to_a_new_connection(self):
        pkt1 = build_tcp_packet(self.h2_mac, self.PRIVATE_MAC, self.h2_ip, self.server_ip, 40000, 80)
        self.router.handle_outgoing(make_event(pkt1, self.h2_port))
        pub_port = list(self.router.nat_table.values())[0]

        removed_event = MagicMock()
        removed_event.ofp.match.nw_proto = protorouter.PROTO_TCP
        removed_event.ofp.match.nw_src = self.h2_ip
        removed_event.ofp.match.tp_src = 40000
        removed_event.ofp.match.nw_dst = self.server_ip
        removed_event.ofp.match.tp_dst = 80
        self.router._handle_FlowRemoved(removed_event)

        # Nueva conexión (otro 5-tuple) debería poder recibir el puerto liberado
        pkt2 = build_tcp_packet(self.h3_mac, self.PRIVATE_MAC, self.h3_ip, self.server_ip, 40000, 80)
        self.router.handle_outgoing(make_event(pkt2, self.h3_port))
        self.assertEqual(len(self.router.nat_table), 1)


# ===========================================================================
# 7. Casos límite / robustez
# ===========================================================================

class TestEdgeCases(BaseRouterTest):

    def test_non_tcp_udp_protocol_is_ignored_by_nat(self):
        """Por ejemplo ICMP (ping): no debe romper, simplemente no es
        traducido (queda fuera del alcance de PAT pedido por la consigna)."""
        icmp_ip = ipv4()
        icmp_ip.protocol = 1  # ICMP_PROTOCOL
        icmp_ip.srcip = self.h2_ip
        icmp_ip.dstip = self.server_ip
        icmp_ip.payload = b"\x08\x00\x00\x00\x00\x00\x00\x00"  # icmp echo crudo

        eth = ethernet()
        eth.type = ethernet.IP_TYPE
        eth.src = self.h2_mac
        eth.dst = self.PRIVATE_MAC
        eth.payload = icmp_ip
        pkt = ethernet(raw=eth.pack())

        try:
            self.router.handle_outgoing(make_event(pkt, self.h2_port))
        except Exception as e:
            self.fail(f"Paquete ICMP no debe crashear el controlador: {e}")
        self.assertEqual(len(self.router.nat_table), 0)

    def test_malformed_packet_in_is_dropped_safely(self):
        event = MagicMock()
        event.parsed.parsed = False
        try:
            self.router._handle_PacketIn(event)
        except Exception as e:
            self.fail(f"Un PacketIn no parseable no debe crashear el controlador: {e}")

    def test_non_ip_non_arp_ethertype_is_ignored(self):
        eth = ethernet()
        eth.type = 0x88CC  # LLDP, por ejemplo
        eth.src = self.h2_mac
        eth.dst = ETHER_BROADCAST
        eth.payload = b"\x00" * 20
        pkt = ethernet(raw=eth.pack())
        event = make_event(pkt, self.h2_port)
        try:
            self.router._handle_PacketIn(event)
        except Exception as e:
            self.fail(f"Ethertype desconocido no debe crashear: {e}")
        self.assertEqual(len(self.mock_connection.send.call_args_list), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
