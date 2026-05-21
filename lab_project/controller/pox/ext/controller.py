from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet
from pox.lib.addresses import EthAddr
import struct
from pox.lib.packet import arp
from pox.lib.addresses import IPAddr

log = core.getLogger()

class Controller(object):

    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info("Switch conectado: dpid=%s puertos=%s",
                 dpid_to_str(event.dpid),
                 [p.port_no for p in event.ofp.ports])

        for port in event.ofp.ports:
            if port.port_no < 65000:   # saltar puertos reservados como LOCAL (65534)
                self.send_discovery_message(event.connection, port.port_no)

    def _handle_PacketIn(self, event):
        packet = event.parsed     # paquete parseado(campos disponibles en vez de leer bit a bit)
        dpid   = event.dpid       # switch que lo envio
        port   = event.port       # puerto por el que recibimos

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