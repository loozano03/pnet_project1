from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet
from pox.lib.addresses import EthAddr
import struct
from pox.lib.packet import arp
from pox.lib.addresses import IPAddr
from pox.lib.packet import ipv4, tcp
from pox.lib.recoco import Timer


log = core.getLogger()

class Controller(object):

    def __init__(self):
        core.openflow.addListeners(self)

        self.collectors ={
        # relaciones IP -> collector para saber a que entrenamiento pertenece un flujo
            "10.0.1.1":"c1",
            "10.0.1.2":"c2",
            "10.0.1.3":"c3",
            "10.0.1.4":"c4",
        }
        #para cada collector guardamos los workers que descubre, evitando duplicados
        self.trainings={
            "c1":set(),
            "c2":set(),
            "c3":set(),
            "c4":set(),
        }
        self.seen_flows = set()

        self.links = {}
        Timer(5, self.send_all_discovery, recurring=True)

        self.switch_neighbors = {}   # dpid -> set de dpids vecinos
        self.leaves = set()          # dpids que son leaves
        self.spines = set()          # dpids que son spines
        Timer(10, self.classify_switches, recurring=True)

        #mapeo de puetos leaf spine
        self.dpid_full = {}        # dpid_truncado -> dpid_completo
        self.leaf_to_spine = {}    # leaf_dpid -> {spine_dpid: puerto}

        self.broadcast_spine = None   # spine elegido como arbol para broadcast
        log.info("Controller initialized: Worker Discovery enabled")

    def flood_arbol(self, event):
        dpid = event.dpid
        in_port = event.port
        dpid_trunc = dpid & 0xFFFFFFFF

        con = core.openflow.getConnection(dpid)
        if con is None:
            return

        out_ports = []
        es_spine = dpid in self.spines

        for port in con.features.ports:
            p = port.port_no
            if p >= 65000:
                continue
            if p == in_port:
                continue

            es_uplink = (dpid_trunc, p) in self.links

            if es_spine:
                # El spine de broadcast reenvia a TODOS sus leaves
                # (solo actua el spine de broadcast; los demas no deberian recibir)
                if dpid == self.broadcast_spine:
                    out_ports.append(p)
            else:
                # Es un leaf
                if not es_uplink:
                    # puerto de host: incluir
                    out_ports.append(p)
                else:
                    # uplink: solo el que va al spine de broadcast
                    vecino_dpid = self.links[(dpid_trunc, p)][0]
                    if vecino_dpid == self.broadcast_spine:
                        out_ports.append(p)

        log.info("flood_arbol: dpid=%s in_port=%s out_ports=%s es_spine=%s",
                 dpid_to_str(dpid), in_port, out_ports, es_spine)

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        for p in out_ports:
            msg.actions.append(of.ofp_action_output(port=p))
        event.connection.send(msg)

    def build_leaf_to_spine(self):
        self.leaf_to_spine = {}
        # Elegir un spine fijo como arbol de broadcast (siempre el mismo)
        if self.spines and self.broadcast_spine is None:
            self.broadcast_spine = sorted(self.spines)[0]

        for (sender_trunc, sender_port), (receiver_dpid, receiver_port) in self.links.items():
            # Recuperar el dpid completo del emisor
            sender_dpid = self.dpid_full.get(sender_trunc)
            if sender_dpid is None:
                continue

            # Nos interesan solo enlaces leaf a spine
            if sender_dpid in self.leaves and receiver_dpid in self.spines:
                if sender_dpid not in self.leaf_to_spine:
                    self.leaf_to_spine[sender_dpid] = {}
                self.leaf_to_spine[sender_dpid][receiver_dpid] = sender_port
        
        for leaf, spines in self.leaf_to_spine.items():
            for spine, port in spines.items():
                log.info("Ruta: leaf %s --puerto %d--> spine %s",
                         dpid_to_str(leaf), port, dpid_to_str(spine))


    def classify_switches(self):
        # Construir el mapa de vecinos a partir de self.links
        self.switch_neighbors = {}

        for (sender_dpid, sender_port), (receiver_dpid, receiver_port) in self.links.items():
            # El receiver_dpid es el dpid completo; el sender es el truncado
            # Agrupamos por el receiver (que tenemos completo)
            if receiver_dpid not in self.switch_neighbors:
                self.switch_neighbors[receiver_dpid] = set()
            self.switch_neighbors[receiver_dpid].add(sender_dpid)

        # Clasificamos segun numero de vecinos
        self.leaves = set()
        self.spines = set()

        for dpid, neighbors in self.switch_neighbors.items():
            if len(neighbors) >= 3:
                self.spines.add(dpid)
            else:
                self.leaves.add(dpid)

        #hacemos log solo si no se ha repetido para no entrar en un bucle
        estado_actual = (frozenset(self.spines), frozenset(self.leaves))

        if estado_actual != getattr(self, "_last_classification", None):
            self._last_classification = estado_actual

            log.info("Clasificacion: %d spines, %d leaves",
                     len(self.spines), len(self.leaves))
            for dpid in self.spines:
                log.info("  SPINE: %s (%d vecinos)",
                         dpid_to_str(dpid), len(self.switch_neighbors[dpid]))
            for dpid in self.leaves:
                log.info("  LEAF:  %s (%d vecinos)",
                         dpid_to_str(dpid), len(self.switch_neighbors[dpid]))
                
        self.build_leaf_to_spine()
            
        

    def send_all_discovery(self):
        for connection in core.openflow.connections:
            ports = connection.features.ports
            for port in ports:
                if port.port_no < 65000:
                    self.send_discovery_message(connection, port.port_no)

    def _handle_ConnectionUp(self, event):
        log.info("Switch conectado: dpid=%s puertos=%s",
                 dpid_to_str(event.dpid),
                 [p.port_no for p in event.ofp.ports])
        # enlazamos el dpid truncado a uno completo
        self.dpid_full[event.dpid & 0xFFFFFFFF] = event.dpid

        #IMPORTANTE
        #SOL BUGG BROADCAST,
        #en nuestros  paquetes de send discovery son broadcast y entonces estabamos volviendo a enveiarnos al controlador
        #en un buclle infinito, que genera lag en la conexion

        # Regla para capturar SOLO los paquetes de discovery (ARP) -> solo al controlador
        msg = of.ofp_flow_mod()
        msg.priority = 200
        msg.match.dl_type = ethernet.ARP_TYPE
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER, max_len=128))
        event.connection.send(msg)

        # regla Table-miss: si el switch no sabe que hacer con un paquete, lo envia al controlador como PacketIn
        msg = of.ofp_flow_mod()
        msg.priority =0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER, max_len=128))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        event.connection.send(msg)

        

        for port in event.ofp.ports:
            if port.port_no < 65000:   # saltar puertos reservados como LOCAL (65534)
                self.send_discovery_message(event.connection, port.port_no)

    def _handle_PacketIn(self, event):
        packet = event.parsed     # paquete parseado(campos disponibles en vez de leer bit a bit)
        dpid   = event.dpid       # switch que lo envio
        port   = event.port       # puerto por el que recibimos
        #log.info("PacketIn received: type=%s dpid=%s port=%s", packet.type, dpid_to_str(event.dpid), event.port)
        if not packet.parsed:
           return
        
        #ignoramos ARP para Worker Discovery.
    
        # Procesar ARP: puede ser discovery (opcode 88) o ARP normal
        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.payload

            if arp_pkt.opcode == 88:
                sender_dpid = arp_pkt.protosrc.toUnsigned()
                sender_port = arp_pkt.protodst.toUnsigned()
                receiver_dpid = event.dpid
                receiver_port = event.port

                clave = (sender_dpid, sender_port)

                # Solo loguear si es un enlace nuevo
                if clave not in self.links:
                    self.links[clave] = (receiver_dpid, receiver_port)
                    log.info("Enlace descubierto: %d:%d --> %s:%d",
                             sender_dpid, sender_port,
                             dpid_to_str(receiver_dpid), receiver_port)
                return
            # ARP normal de un host: inundar de forma controlada (arbol)
            self.flood_arbol(event)
            return


        ip_pkt = packet.find('ipv4')
        if ip_pkt is None:
            return

        tcp_pkt = packet.find('tcp')
        if tcp_pkt is None:
            return

        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        dst_port = tcp_pkt.dstport

        #solo nos interesan flujos TCP hacia collectors conocidos
        if dst_ip not in self.collectors:
            return

        collector = self.collectors[dst_ip]

        if not src_ip.startswith("10.0.0."):
            return

        worker_number = src_ip.split(".")[-1]
        worker_id = "w%s" % worker_number

        #identificador único del worker
        flow_id = (worker_id, collector)

        #si ya hemos visto este worker para este collector, no lo registramos otra vez
        if flow_id in self.seen_flows:
            return

        self.seen_flows.add(flow_id)

        if worker_id not in self.trainings[collector]:
            self.trainings[collector].add(worker_id)

            log.info(
                "Worker discovered from TCP flow: %s -> %s (%s:%s) | Kv=%d",
                worker_id,
                collector,
                dst_ip,
                dst_port,
                len(self.trainings[collector])
            )

#ya que el controlador solo sabe el num de los switches q estan directamente conectados a el y sus puertos conectados
#tenemos descubrir los dispositivos que tambien forman parte de esta red
#informacion sobre los switches como dpid y puertos que se conectan entre ellos

#lab3.1
    def send_discovery_message(self, connection, port_no):
        dpid = connection.dpid
        #creamos arp
        arp_pkt = arp()
        arp_pkt.opcode = 88 # lo marcamos para saber q son nuestros
        # era la manera de poder hacer que cabiese realmente el dpid complet pq en etheret no cabia
        arp_pkt.protosrc = IPAddr(dpid & 0xFFFFFFFF)#pq la dpid es muy larga y aun asi no cabe
        arp_pkt.protodst = IPAddr(port_no)# asiq lo usamos como si fuese una dir IP
        arp_pkt.hwsrc = EthAddr("02:00:00:00:00:00")       # We use a custom MAC prefix
        arp_pkt.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")


        #creamos un paq eth q encapsula la info
        eth=ethernet()
        #importante poner q es un objeto eth no un string
        eth.src = EthAddr("02:00:00:00:%02x:%02x" % (dpid & 0xFF, port_no & 0xFF))
        eth.dst=EthAddr("ff:ff:ff:ff:ff:ff")
        eth.type=ethernet.ARP_TYPE#0x0806
        eth.payload=arp_pkt

        #difundimos paq
        msg = of.ofp_packet_out()
        msg.data=eth.pack()
        msg.actions.append(of.ofp_action_output(port=port_no))
        connection.send(msg)


def launch():
    core.registerNew(Controller)