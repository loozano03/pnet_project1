from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet
from pox.lib.addresses import EthAddr
import struct
from pox.lib.packet import arp
from pox.lib.addresses import IPAddr
from pox.lib.packet import ipv4, tcp

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
        log.info("Controller initialized: Worker Discovery enabled")

    def _handle_ConnectionUp(self, event):
        log.info("Switch conectado: dpid=%s puertos=%s",
                 dpid_to_str(event.dpid),
                 [p.port_no for p in event.ofp.ports])

        # regla Table-miss: si el switch no sabe que hacer con un paquete, lo envia al controlador como PacketIn
        msg = of.ofp_flow_mod()
        msg.priority =0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER, max_len=128))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        event.connection.send(msg)

        for collector_ip in self.collectors.keys():
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match = of.ofp_match(
                dl_type=ethernet.IP_TYPE,
                nw_proto=6,
                nw_dst=IPAddr(collector_ip)
            )
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
    
        if packet.type == ethernet.ARP_TYPE:
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

        #si ya hemos visto este flujo, no volvemos a registrarlo
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