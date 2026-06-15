# Import some POX stuff
from pox.core import core                              # Main POX object
import pox.openflow.libopenflow_01 as of                # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr           # Address types
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")      # Red interna
PRIVATE_MASK = 24                           # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")        # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")           # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")   # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1                             # Puerto del switch conectado a la red pública

IP_ANY = IPAddr("0.0.0.0")                  # Usado para descartar ARP probes (src 0.0.0.0)

# Punto 6.2: Manejo de ARP --------------------------------------
ARP_RETRY_INTERVAL = 2   # Segundos entre reintentos de ARP Request
ARP_MAX_RETRIES = 5      # Cantidad máxima de reintentos antes de descartar


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # Punto 6.2: Tabla ARP dinámica.
        # Mapea IPAddr -> (EthAddr, puerto del switch).
        # Se completa exclusivamente a partir de tráfico observado
        # (ARP Requests, ARP Replies y paquetes IP). No hay entradas
        # estáticas ni hardcodeadas.
        self.arp_table = {}

        # Punto 6.2: Paquetes IP en espera de resolución ARP.
        # Mapea IPAddr -> {"events": [PacketIn, ...], "retries": int}
        self.pending = {}

        # Reintento periódico de ARP Requests sin respuesta.
        Timer(ARP_RETRY_INTERVAL, self._retry_pending_arps, recurring=True)

    # ----------------------------------------------------------------
    # Dispatcher principal
    # ----------------------------------------------------------------
    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        packet = event.parsed

        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        elif packet.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo distinto de IPv4/ARP (0x{packet.type:04x}).")

    # ----------------------------------------------------------------
    # Punto 6.2: Manejo de ARP
    # ----------------------------------------------------------------
    def handle_arp(self, event):
        packet = event.parsed
        arp_pkt = packet.payload
        in_port = event.port

        if arp_pkt.opcode == arp.REQUEST:
            log_color(
                YELLOW,
                f"ARP REQUEST: ¿quién tiene {arp_pkt.protodst}? "
                f"(preguntado por {arp_pkt.protosrc}/{arp_pkt.hwsrc}, puerto {in_port})")
        elif arp_pkt.opcode == arp.REPLY:
            log_color(
                YELLOW,
                f"ARP REPLY: {arp_pkt.protosrc} está en {arp_pkt.hwsrc} (puerto {in_port})")
        else:
            log_color(YELLOW, f"ARP con opcode desconocido ({arp_pkt.opcode}), se ignora.")
            return

        # Aprendizaje dinámico: cualquier ARP Request o ARP Reply que
        # cruza el switch nos da una asociación (IP, MAC, puerto) válida.
        if arp_pkt.protosrc != IP_ANY:
            self.learn(arp_pkt.protosrc, arp_pkt.hwsrc, in_port)

        if arp_pkt.opcode == arp.REQUEST:
            self.handle_arp_request(arp_pkt, in_port)
        else:
            # Si alguien estaba esperando esta MAC, se reprocesan los
            # paquetes IP que habían quedado pendientes.
            self.resolve_pending(arp_pkt.protosrc)

    def handle_arp_request(self, arp_pkt, in_port):
        """Responde ARP Requests dirigidas a las IP propias del router (NAT)."""
        if in_port == PUBLIC_PORT and arp_pkt.protodst == PUBLIC_IP:
            our_mac = PUBLIC_MAC
        elif in_port != PUBLIC_PORT and arp_pkt.protodst == PRIVATE_IP:
            our_mac = PRIVATE_MAC
        else:
            log_color(
                RED,
                f"ARP REQUEST ignorado: {arp_pkt.protodst} no es una IP propia "
                f"para la interfaz del puerto {in_port}")
            return

        log_color(GREEN, f"ARP REPLY: {arp_pkt.protodst} está en {our_mac} -> puerto {in_port}")
        self.send_arp_reply(arp_pkt, our_mac, in_port)

    # ----------------------------------------------------------------
    # Construcción y envío de paquetes ARP
    # ----------------------------------------------------------------
    def send_arp_reply(self, arp_req, our_mac, out_port):
        arp_reply = arp()
        arp_reply.hwtype = arp_req.hwtype
        arp_reply.prototype = arp_req.prototype
        arp_reply.hwlen = arp_req.hwlen
        arp_reply.protolen = arp_req.protolen
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = our_mac
        arp_reply.hwdst = arp_req.hwsrc
        arp_reply.protosrc = arp_req.protodst
        arp_reply.protodst = arp_req.protosrc

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = our_mac
        eth.dst = arp_req.hwsrc
        eth.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def send_arp_request(self, target_ip):
        """Genera un ARP Request para resolver `target_ip`.

        Si `target_ip` pertenece a la red privada, se inunda por los
        puertos del switch (no se conoce a priori en qué puerto está el
        host privado). Si pertenece a la red pública, se envía únicamente
        por el puerto público (PUBLIC_PORT).
        """
        if target_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            src_ip = PRIVATE_IP
            src_mac = PRIVATE_MAC
            out_port = of.OFPP_FLOOD
        else:
            src_ip = PUBLIC_IP
            src_mac = PUBLIC_MAC
            out_port = PUBLIC_PORT

        arp_req = arp()
        arp_req.opcode = arp.REQUEST
        arp_req.hwsrc = src_mac
        arp_req.hwdst = ETHER_BROADCAST
        arp_req.protosrc = src_ip
        arp_req.protodst = target_ip

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = src_mac
        eth.dst = ETHER_BROADCAST
        eth.payload = arp_req

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

        log_color(CYAN, f"ARP REQUEST enviado: ¿quién tiene {target_ip}? (desde {src_ip}/{src_mac})")

    # ----------------------------------------------------------------
    # Tabla ARP y cola de paquetes pendientes de resolución
    # ----------------------------------------------------------------
    def learn(self, ip, mac, port):
        prev = self.arp_table.get(ip)
        if prev != (mac, port):
            log_color(CYAN, f"ARP LEARN: {ip} -> {mac} (puerto {port})")
        self.arp_table[ip] = (mac, port)

    def resolve_mac(self, ip):
        """Devuelve (mac, puerto) si `ip` está en la tabla ARP, o None si no se conoce."""
        return self.arp_table.get(ip)

    def queue_pending(self, ip, event):
        """Encola un PacketIn a la espera de la resolución ARP de `ip`."""
        entry = self.pending.setdefault(ip, {"events": [], "retries": 0})
        entry["events"].append(event)
        if entry["retries"] == 0:
            self.send_arp_request(ip)
            entry["retries"] = 1

    def resolve_pending(self, ip):
        """Reprocesa los paquetes IP que esperaban la MAC de `ip`."""
        entry = self.pending.pop(ip, None)
        if not entry:
            return
        log_color(CYAN, f"ARP resuelto para {ip}: reprocesando {len(entry['events'])} paquete(s) pendiente(s)")
        for event in entry["events"]:
            self.handle_ip(event)

    def _retry_pending_arps(self):
        """Reintenta (o descarta tras demasiados intentos) las resoluciones ARP pendientes."""
        for ip in list(self.pending.keys()):
            entry = self.pending[ip]
            if entry["retries"] >= ARP_MAX_RETRIES:
                log_color(
                    RED,
                    f"ARP: {ip} no respondió tras {ARP_MAX_RETRIES} intentos, "
                    f"se descartan {len(entry['events'])} paquete(s) pendiente(s)")
                del self.pending[ip]
                continue
            self.send_arp_request(ip)
            entry["retries"] += 1

    # ----------------------------------------------------------------
    # Manejo de IPv4
    # ----------------------------------------------------------------
    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        # TP2 - Punto 6.2: aprendemos (IP, MAC, puerto) del host que envía
        # el paquete. Esto alimenta la tabla ARP dinámica.
        self.learn(ip_pkt.srcip, packet.src, in_port)

        if not ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}")
            return

        log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")

        # TP2 - Punto 6.2: en vez de una MAC de destino hardcodeada
        # (H1_MAC), se resuelve dinámicamente mediante ARP. Si todavía
        # no se conoce, el paquete se encola y se dispara un ARP Request;
        # cuando llegue la respuesta (handle_arp -> resolve_pending) este
        # mismo método se vuelve a invocar para terminar de procesarlo.
        resolved = self.resolve_mac(ip_pkt.dstip)
        if resolved is None:
            log_color(YELLOW, f"MAC de {ip_pkt.dstip} desconocida, resolviendo por ARP antes de continuar...")
            self.queue_pending(ip_pkt.dstip, event)
            return

        dst_mac, dst_port = resolved

        # Instalar Flujo Saliente
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 10

        # Filtro (Saliente)
        fm.match.nw_src = ip_pkt.srcip
        fm.match.nw_dst = ip_pkt.dstip
        fm.match.dl_type = 0x800  # IPv4
        fm.match.in_port = in_port

        # Acción (Saliente)
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=dst_port))
        self.connection.send(fm)

        # Instalar Flujo Entrante (para la respuesta)
        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = 10

        # Filtro (Entrante)
        fm_back.match.nw_src = ip_pkt.dstip
        fm_back.match.nw_dst = ip_pkt.srcip
        fm_back.match.dl_type = 0x800  # IPv4
        fm_back.match.in_port = dst_port

        # Acción (Entrante)
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
        fm_back.actions.append(of.ofp_action_output(port=in_port))
        self.connection.send(fm_back)

        # Reenviar el paquete actual con las MACs ya traducidas
        # (los paquetes siguientes de este flujo pasan directo por las
        # reglas instaladas, sin intervención del controlador).
        packet.src = PUBLIC_MAC
        packet.dst = dst_mac
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=dst_port))
        log_color(
            CYAN,
            f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {PUBLIC_MAC} → {dst_mac} | Out Port: {dst_port}")
        self.connection.send(msg)


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
