# Import some POX stuff
from pox.core import core                              # Main POX object
import pox.openflow.libopenflow_01 as of                # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr           # Address types
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer
from dataclasses import dataclass

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

# Punto 6.3: NAT por puertos (PAT) ------------------------------
TCP_TIMEOUT = 300      # 5 minutos para TCP establecido
TCP_FIN_TIMEOUT = 30   # 30 segundos después de FIN
UDP_TIMEOUT = 30       # 30 segundos para UDP
NAT_PORT_START = 10000
NAT_PORT_END = 11000

PROTO_TCP = 6
PROTO_UDP = 17


@dataclass(frozen=True)
class NatKey:
    """Clave de una conexión NAT: identifica un flujo de forma única.

    Es frozen=True para ser hasheable y poder usarse como clave de
    nat_table y como valor en used_ports.
    """
    src_ip: IPAddr
    src_port: int
    dst_ip: IPAddr
    dst_port: int
    proto: int


@dataclass
class NatInfo:
    """Datos de una traducción NAT. Base común."""
    key: NatKey
    pub_port: int
    src_ip: IPAddr
    src_port: int
    proto: int
    in_port: int
    original_mac_src: EthAddr


@dataclass
class OutgoingNatInfo(NatInfo):
    """Tráfico privada -> pública. El próximo salto es el host público."""
    dst_ip: IPAddr
    dst_port: int
    dst_mac: EthAddr
    dst_port_switch: int


@dataclass
class IncomingNatInfo(NatInfo):
    """Tráfico pública -> privada. El próximo salto es el host privado."""
    priv_ip: IPAddr
    priv_port: int
    priv_mac: EthAddr
    priv_port_switch: int


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

        # Punto 6.3: NAT por puertos (PAT)
        self.nat_table = {} # Mapea NatKey -> PuertoPublico
        self.available_ports = set(range(NAT_PORT_START, NAT_PORT_END + 1)) # Puertos públicos disponibles para asignar a hosts privados
        self.used_ports = {} # Puertos actualmente asignados



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

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            # Saliente (Privado -> Público)
            log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")
            self.handle_outgoing(event)
        else:
            # Entrante (Público -> Privado)
            log_color(CYAN, f"MATCH: {ip_pkt.srcip} pertenece a la red pública")
            self.handle_incoming(event)


    # ----------------------------------------------------------------
    # Manejo de NAT por puertos (PAT)
    # ----------------------------------------------------------------
    def assign_public_port(self): 
        if not self.available_ports:
            log_color(RED, "No hay puertos públicos disponibles para asignar a hosts privados.")
            return None
        port = self.available_ports.pop()
        return port
        
    def release_public_port(self, pub_port):
        if pub_port in self.used_ports:
            key = self.used_ports.pop(pub_port)
            self.nat_table.pop(key, None)
            self.available_ports.add(pub_port)

    @staticmethod
    def extract_transport(ip_pkt):
        if ip_pkt.protocol == PROTO_TCP:
            tcp = ip_pkt.payload
            return PROTO_TCP, tcp.srcport, tcp.dstport
        elif ip_pkt.protocol == PROTO_UDP:
            udp = ip_pkt.payload
            return PROTO_UDP, udp.srcport, udp.dstport
        else:
            return None, None, None

    def get_or_create_nat_entry(self, key):
        if key in self.nat_table:
            return self.nat_table[key]
        else:
            pub_port = self.assign_public_port()
            if pub_port is None:
                return None
            self.nat_table[key] = pub_port
            self.used_ports[pub_port] = key
            log_color(GREEN, f"Nueva entrada NAT creada: {key} -> puerto público {pub_port}")
            return pub_port

    def handle_outgoing(self, event): 
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port
        
        proto, src_port, dst_port = self.extract_transport(ip_pkt)
        if proto is None:
            # No es TCP/UDP, ignorar
            log_color(YELLOW, f"Paquete no TCP/UDP, ignorado por NAT: protocolo {ip_pkt.protocol}")
            return
        log_color(CYAN, f"Paquete outgoing: {ip_pkt.srcip}:{src_port} -> {ip_pkt.dstip}:{dst_port} (proto {proto})")
        
        # TP2 - Punto 6.2: en vez de una MAC de destino hardcodeada
        # (H1_MAC), se resuelve dinámicamente mediante ARP. Si todavía
        # no se conoce, el paquete se encola y se dispara un ARP Request;
        # cuando llegue la respuesta (handle_arp -> resolve_pending) este
        # mismo método se vuelve a invocar para terminar de procesarlo.

        # Resolver MAC destino
        resolved = self.resolve_mac(ip_pkt.dstip)
        if resolved is None:
            log_color(YELLOW, f"MAC de {ip_pkt.dstip} desconocida, resolviendo por ARP...")
            self.queue_pending(ip_pkt.dstip, event)
            return
        dst_mac, dst_port_switch = resolved
        

        # TP2 - Punto 6.3: NAT por puertos (PAT) - tráfico saliente.
        # Procesa paquetes que van de la red privada a la red pública.
        # - Detecta TCP/UDP y extrae puertos
        # - Crea/actualiza entrada en tabla NAT
        # - Traduce IP origen y puerto origen
        # - Prepara datos para instalación de flujos (event.nat_info)
        # - Reenvía el paquete traducido

        # Buscar/Crear entrada NAT
        key = NatKey(ip_pkt.srcip, src_port, ip_pkt.dstip, dst_port, proto)
        pub_port = self.get_or_create_nat_entry(key)
        if pub_port is None:
            log_color(RED, f"No se pudo asignar puerto público para {key}, paquete droppeado")
            return
        
        # Info para usar en instalación de flujos
        event.nat_info = OutgoingNatInfo(
            key=key,
            pub_port=pub_port,
            src_ip=ip_pkt.srcip,
            src_port=src_port,
            proto=proto,
            in_port=in_port,
            original_mac_src=packet.src,
            dst_ip=ip_pkt.dstip,
            dst_port=dst_port,
            dst_mac=dst_mac,
            dst_port_switch=dst_port_switch,
        )

        original_src_ip = ip_pkt.srcip
        original_src_port = src_port

        # Traducción del paquete actual (solo para este paquete, 
        # los siguientes pasan directo por las reglas de flujo)
        ip_pkt.srcip = PUBLIC_IP
        if proto == PROTO_TCP:
            ip_pkt.payload.srcport = pub_port
        elif proto == PROTO_UDP:
            ip_pkt.payload.srcport = pub_port
        
        packet.src = PUBLIC_MAC
        packet.dst = dst_mac

        # Reenviar el paquete actual con las MACs ya traducidas
        # (los paquetes siguientes de este flujo pasan directo por las
        # reglas instaladas, sin intervención del controlador).
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=dst_port_switch))
        log_color(
            CYAN,
            f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {PUBLIC_MAC} → {dst_mac} | Out Port: {dst_port}")
        self.connection.send(msg)
        log_color(GREEN, f"Paquete traducido y enviado: {PUBLIC_IP}:{pub_port} -> {ip_pkt.dstip}:{dst_port} (proto {proto})")

        # Instalación del flujo saliente.
        # A partir de acá el switch traduce y reenvía esta conexión sin
        # intervención del controlador (hasta que el flujo lo expire).
        info = event.nat_info
        self.install_outgoing_flow(
            proto=info.proto, priv_ip=info.src_ip, priv_port=info.src_port,
            server_ip=info.dst_ip, server_port=info.dst_port, pub_port=info.pub_port,
            in_port=info.in_port, server_mac=info.dst_mac, out_port=info.dst_port_switch)


    def handle_incoming(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port
        
        proto, src_port, dst_port = self.extract_transport(ip_pkt)
        if proto is None:
            log_color(YELLOW, f"Paquete no TCP/UDP, ignorado para NAT entrante")
            return
        
        log_color(CYAN, f"INCOMING: {ip_pkt.srcip}:{src_port} → {ip_pkt.dstip}:{dst_port} (proto={proto})")

        # TP2 - Punto 6.3: NAT por puertos (PAT) - tráfico entrante.
        # Procesa paquetes que van de la red pública a la red privada.
        # - Busca en tabla NAT por puerto público destino
        # - Destraduce IP destino y puerto destino
        # - Prepara datos para instalación de flujos (event.nat_info)
        # - Reenvía el paquete destraducido
        
        # Buscar en tabla NAT
        if dst_port not in self.used_ports:
            log_color(YELLOW, f"Puerto {dst_port} no está en uso por NAT, ignorando")
            return
        
        key = self.used_ports[dst_port]
        # El flujo se registró en el sentido saliente, así que el origen de
        # la clave es el host privado y el destino es el host público.
        priv_ip = key.src_ip
        priv_port = key.src_port
        proto_match = key.proto
        
        if proto != proto_match:
            log_color(YELLOW, f"Protocolo no coincide: {proto} vs {proto_match}")
            return
        
        log_color(CYAN, f"NAT ENCONTRADO: puerto {dst_port} → {priv_ip}:{priv_port}")
        
        # Resolver MAC privada
        resolved = self.resolve_mac(priv_ip)
        if resolved is None:
            log_color(YELLOW, f"MAC de {priv_ip} desconocida, resolviendo por ARP...")
            self.queue_pending(priv_ip, event)
            return
        priv_mac, priv_port_switch = resolved
        
        # ===== DATOS PARA FLUJOS =====
        event.nat_info = IncomingNatInfo(
            key=key,
            pub_port=dst_port,
            src_ip=ip_pkt.srcip,
            src_port=src_port,
            proto=proto,
            in_port=in_port,
            original_mac_src=packet.src,
            priv_ip=priv_ip,
            priv_port=priv_port,
            priv_mac=priv_mac,
            priv_port_switch=priv_port_switch,
        )
        
        # Destraduccion del paquete actual
        ip_pkt.dstip = priv_ip
        if proto == PROTO_TCP:
            ip_pkt.payload.dstport = priv_port
        elif proto == PROTO_UDP:
            ip_pkt.payload.dstport = priv_port
        
        packet.src = PRIVATE_MAC
        packet.dst = priv_mac
        
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=priv_port_switch))
        self.connection.send(msg)
        
        log_color(GREEN, f"PAQUETE DESTRADUCIDO: {ip_pkt.srcip}:{src_port} → {priv_ip}:{priv_port}")
        
        # Instalación del flujo entrante.
        # Las respuestas siguientes las toma el switch.
        info = event.nat_info
        self.install_incoming_flow(
            proto=info.proto, server_ip=info.src_ip, server_port=info.src_port,
            pub_port=info.pub_port, in_port=info.in_port, priv_ip=info.priv_ip,
            priv_port=info.priv_port, priv_mac=info.priv_mac, out_port=info.priv_port_switch)

    @staticmethod
    def _get_nat_timeout(proto):
        if proto == PROTO_TCP:
            return TCP_TIMEOUT
        elif proto == PROTO_UDP:
            return UDP_TIMEOUT
        else:
            return None

    # ----------------------------------------------------------------
    # Punto 6.4: instalación de flujos OpenFlow
    # ----------------------------------------------------------------
    def install_outgoing_flow(self, proto, priv_ip, priv_port, server_ip,
                              server_port, pub_port, in_port, server_mac, out_port):
        """Flujo saliente (privada -> pública): traduce origen IP+puerto+MAC.

        Lleva SEND_FLOW_REM: este flujo es el dueño del ciclo de vida de la
        conexión y dispara la liberación de recursos al expirar.
        """
        fm = of.ofp_flow_mod()
        fm.idle_timeout = self._get_nat_timeout(proto)
        fm.flags |= of.OFPFF_SEND_FLOW_REM
        m = fm.match
        m.in_port = in_port                 # puerto del switch del host privado
        m.dl_type = 0x800                   # IPv4
        m.nw_proto = proto
        m.nw_src = priv_ip
        m.nw_dst = server_ip
        m.tp_src = priv_port
        m.tp_dst = server_port
        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        fm.actions.append(of.ofp_action_tp_port.set_src(pub_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        fm.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(fm)
        log_color(GREEN, f"FLUJO SALIENTE instalado: {priv_ip}:{priv_port} -> "
                         f"{server_ip}:{server_port} (pub_port {pub_port})")

    def install_incoming_flow(self, proto, server_ip, server_port, pub_port,
                              in_port, priv_ip, priv_port, priv_mac, out_port):
        """Flujo entrante (pública -> privada): destraduce destino IP+puerto+MAC.

        No lleva SEND_FLOW_REM: el flujo saliente es el dueño del ciclo de vida;
        este se borra explícitamente en el teardown o expira por idle en silencio.
        """
        fm = of.ofp_flow_mod()
        fm.idle_timeout = self._get_nat_timeout(proto)
        m = fm.match
        m.in_port = in_port                 # PUBLIC_PORT
        m.dl_type = 0x800                   # IPv4
        m.nw_proto = proto
        m.nw_src = server_ip
        m.nw_dst = PUBLIC_IP
        m.tp_src = server_port
        m.tp_dst = pub_port
        fm.actions.append(of.ofp_action_nw_addr.set_dst(priv_ip))
        fm.actions.append(of.ofp_action_tp_port.set_dst(priv_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(priv_mac))
        fm.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(fm)
        log_color(GREEN, f"FLUJO ENTRANTE instalado: {server_ip}:{server_port} -> "
                         f"pub_port {pub_port} -> {priv_ip}:{priv_port}")

    def _delete_incoming_flow(self, server_ip, server_port, pub_port, proto):
        """Borra explícitamente el flujo entrante asociado a una conexión."""
        fm = of.ofp_flow_mod()
        fm.command = of.OFPFC_DELETE
        m = fm.match
        m.in_port = PUBLIC_PORT
        m.dl_type = 0x800
        m.nw_proto = proto
        m.nw_src = server_ip
        m.nw_dst = PUBLIC_IP
        m.tp_src = server_port
        m.tp_dst = pub_port
        self.connection.send(fm)

    def _handle_FlowRemoved(self, event):
        """Libera recursos cuando un flujo saliente expira."""
        match = event.ofp.match
        if match.nw_proto not in (PROTO_TCP, PROTO_UDP) or match.nw_src is None:
            return
        key = NatKey(match.nw_src, match.tp_src, match.nw_dst, match.tp_dst, match.nw_proto)
        pub_port = self.nat_table.get(key)
        if pub_port is None:
            return  # No es una expiración de flujo saliente que administremos
        # Borrar el flujo entrante asociado antes de liberar el puerto público.
        self._delete_incoming_flow(server_ip=match.nw_dst, server_port=match.tp_dst,
                                   pub_port=pub_port, proto=match.nw_proto)
        self.release_public_port(pub_port)
        log_color(YELLOW, f"NAT liberado: puerto {pub_port} (conexión {key}) expiró")


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
