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
import time


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
        self.flow_byte_counts = {}
        self.flow_active = {}
        self.flow_round_start = {}
        self.flow_stable_counts = {}
        self.flow_stats_source = {}
        self.dv_logged = set()
        self.start_time = None
        self.training_stats ={
            "c1": {"first_seen":None, "flow_times": [], "workers":set(), "cycle_times":[], "last_packet_seen": None, "tv_estimates": [], "last_worker_seen": {}},
            "c2": {"first_seen":None, "flow_times": [], "workers":set(), "cycle_times":[], "last_packet_seen": None, "tv_estimates": [], "last_worker_seen": {}},
            "c3": {"first_seen":None, "flow_times": [], "workers":set(), "cycle_times":[], "last_packet_seen": None, "tv_estimates": [], "last_worker_seen": {}},
            "c4": {"first_seen":None, "flow_times": [], "workers":set(), "cycle_times":[], "last_packet_seen": None, "tv_estimates": [], "last_worker_seen": {}},
        }

        self.host_location = {}   # ip(leaf_dpid, puerto)

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

        self.spine_s1 = None  
        self.spine_s2 = None   

        log.info("Controller initialized: Worker Discovery enabled")

        Timer(2, self.request_flow_stats, recurring=True)

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
        
        # asignamos los spine ordenando los dpid
        if len(self.spines) == 2:
            spines_ordenados = sorted(self.spines)
            self.spine_s1 = spines_ordenados[0]
            self.spine_s2 = spines_ordenados[1]
        
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

        # Aprender ubicacionde worker y host origen (si entro por puerto de acceso, no uplink)
        src_ip_full = str(ip_pkt.srcip)
        dpid_trunc = event.dpid & 0xFFFFFFFF
        es_uplink = (dpid_trunc, event.port) in self.links
        if not es_uplink and src_ip_full not in self.host_location:
            self.host_location[src_ip_full] = (event.dpid, event.port)
            log.info("Host localizado: %s en leaf %s puerto %d",
                     src_ip_full, dpid_to_str(event.dpid), event.port)
        
        tcp_pkt = packet.find('tcp')
        #si no es TCP, no sirver para Worker Discovery
        # pero si que queremos reenviarlo por nuestro arbol sin bucles
        if tcp_pkt is None:
            self.flood_arbol(event)
            return

        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        dst_port = tcp_pkt.dstport

        #solo nos interesan flujos TCP hacia collectors conocidos
        if dst_ip in self.collectors and src_ip.startswith("10.0.0."):
            collector = self.collectors[dst_ip]
            now = time.time()
            if self.start_time is None:
                self.start_time = now
            stats = self.training_stats[collector]

            # Detectar inicio de ciclo usando silencio entre ráfagas.
            # Si pasa más de IDLE_GAP sin ver tráfico de este collector,
            # y luego vuelve a aparecer, asumimos que empieza una nueva ronda.
            IDLE_GAP = 15.0

            last_seen = stats["last_packet_seen"]

            if last_seen is None:
                stats["cycle_times"].append(now)

            elif now - last_seen > IDLE_GAP:
                stats["cycle_times"].append(now)

                if len(stats["cycle_times"]) >= 2:
                    tv_est = stats["cycle_times"][-1] - stats["cycle_times"][-2]
                    stats["tv_estimates"].append(tv_est)

                    log.info(
                        "Traffic characterization: %s Tv_est=%.2fs",
                        collector,
                        tv_est
                    )

            stats["last_packet_seen"] = now
            if stats["first_seen"] is None:
                stats["first_seen"]=now
                phi_est= now-self.start_time
                log.info("Traffic characterization: %s phi_est=%.3fs", collector, phi_est)
            worker_number = src_ip.split(".")[-1]
            worker_id="w%s" % worker_number
            last_worker = stats["last_worker_seen"].get(worker_id)

            if last_worker is None:
                stats["last_worker_seen"][worker_id] = now

            elif now - last_worker > 20:
                tv_est = now - last_worker
                stats["tv_estimates"].append(tv_est)

                log.info(
                    "Traffic characterization: %s Tv_est=%.2fs worker=%s",
                    collector,
                    tv_est,
                    worker_id
                )

                # Actualizamos solo cuando creemos que empezó una nueva ronda
                stats["last_worker_seen"][worker_id] = now
            flow_id =(worker_id, collector)

            #si ya hemos visto este worker para este collector, no lo registramos otra vez
            if flow_id not in self.seen_flows:
                if self.instalar_ruta(src_ip, dst_ip):
                    self.seen_flows.add(flow_id)
                    self.trainings[collector].add(worker_id)
                    stats["workers"].add(worker_id)
                    stats["flow_times"].append(now)

                

                    log.info(
                        "Worker discovered from TCP flow: %s -> %s (%s:%s) | Kv=%d",
                        worker_id,
                        collector,
                        dst_ip,
                        dst_port,
                        len(self.trainings[collector])
                    )
                    log.info(
                        "Traffic characterization: %s Kv=%d",
                        collector,
                        len(stats["workers"])
                    )
        self.flood_arbol(event)
        return

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
    
    def instalar_ruta(self, worker_ip, collector_ip):
        # comprobamos que sabemos donde esta estan los host
        log.info("instalar_ruta llamada: %s -> %s", worker_ip, collector_ip)
        if worker_ip not in self.host_location:
            return False
        if collector_ip not in self.host_location:
            return False

        worker_leaf, worker_port = self.host_location[worker_ip]
        collector_leaf, collector_port = self.host_location[collector_ip]

        # Elegir spine segun paridad del worker
        worker_num = int(worker_ip.split(".")[-1])
        if worker_num % 2 == 1:
            spine = self.spine_s1   
        else:
            spine = self.spine_s2 

        if spine is None:
            return

        # port del leaf del worker hacia el spine elegido
        if worker_leaf not in self.leaf_to_spine:
            return
        if spine not in self.leaf_to_spine[worker_leaf]:
            return
        puerto_worker_a_spine = self.leaf_to_spine[worker_leaf][spine]

        # port leaf del colector hacia el spine elegido
        if collector_leaf not in self.leaf_to_spine:
            return
        if spine not in self.leaf_to_spine[collector_leaf]:
            return
        puerto_colector_a_spine = self.leaf_to_spine[collector_leaf][spine]

        # port del spine hacia el leaf del colector
        #    (buscar en links: del spine, que puerto va al collector_leaf)
        puerto_spine_a_colector = None
        spine_trunc = spine & 0xFFFFFFFF
        for (d, p), (vecino, vp) in self.links.items():
            if d == spine_trunc and vecino == collector_leaf:
                puerto_spine_a_colector = p
                break
        if puerto_spine_a_colector is None:
            return

        # --- INSTALAR REGLAS DE IDA (worker -> colector) ---

        # Regla en el leaf del worker: hacia el colector -> salir por el uplink al spine
        self.instalar_regla(worker_leaf, worker_ip, collector_ip, puerto_worker_a_spine)

        # Regla en el spine: hacia el colector -> bajar al leaf del colector
        self.instalar_regla(spine, worker_ip, collector_ip, puerto_spine_a_colector)

        # Regla en el leaf del colector: hacia el colector -> salir por el puerto del colector
        self.instalar_regla(collector_leaf, worker_ip, collector_ip, collector_port)

        log.info("Ruta instalada: %s -> %s via %s",
                 worker_ip, collector_ip, dpid_to_str(spine))
        return True
        
    def instalar_regla(self, dpid, src_ip, dst_ip, out_port):
        con = core.openflow.getConnection(self.dpid_full.get(dpid & 0xFFFFFFFF, dpid))
        # Si dpid ya es completo, getConnection lo acepta directo
        con = core.openflow.getConnection(dpid)
        if con is None:
            return

        msg = of.ofp_flow_mod()
        msg.priority = 300
        msg.match.dl_type = 0x0800
        msg.match.nw_src = IPAddr(src_ip)
        msg.match.nw_dst = IPAddr(dst_ip)
        msg.actions.append(of.ofp_action_output(port=out_port))
        con.send(msg)

    def request_flow_stats(self):
        for con in core.openflow.connections:
            req = of.ofp_stats_request(body=of.ofp_flow_stats_request())
            con.send(req)


    def _handle_FlowStatsReceived(self, event):
        for f in event.stats:
            if f.priority == 300 and f.match.nw_src is not None and f.match.nw_dst is not None:
                src_ip = str(f.match.nw_src)
                dst_ip = str(f.match.nw_dst)

                if dst_ip not in self.collectors:
                    continue

                flow_key = (src_ip, dst_ip)

                # Elegimos solo un switch como fuente de estadísticas para este flujo
                # para no contar el mismo flujo varias veces.
                if flow_key not in self.flow_stats_source:
                    self.flow_stats_source[flow_key] = event.dpid

                if self.flow_stats_source[flow_key] != event.dpid:
                    continue

                current_bytes = f.byte_count
                previous_bytes = self.flow_byte_counts.get(flow_key)

                self.flow_byte_counts[flow_key] = current_bytes

                if previous_bytes is None:
                    continue

                delta_bytes = current_bytes - previous_bytes

                # Si el contador aumenta, el flujo/ronda está activo
                if delta_bytes > 0:
                    if not self.flow_active.get(flow_key, False):
                        self.flow_active[flow_key] = True
                        self.flow_round_start[flow_key] = previous_bytes

                    self.flow_stable_counts[flow_key] = 0

                # Si no aumenta, puede haber terminado la ronda
                else:
                    if self.flow_active.get(flow_key, False):
                        self.flow_stable_counts[flow_key] = self.flow_stable_counts.get(flow_key, 0) + 1

                        # Esperamos 2 consultas sin crecer para confirmar que terminó
                        if self.flow_stable_counts[flow_key] >= 2:
                            start_bytes = self.flow_round_start.get(flow_key, previous_bytes)
                            round_bytes = current_bytes - start_bytes
                            dv_est = round_bytes * 8.0 / 1e6

                            if dv_est >= 1:
                                log.info(
                                    "Traffic characterization: %s Dv_est=%.2f Mbits flow=%s->%s",
                                    self.collectors[dst_ip],
                                    dv_est,
                                    src_ip,
                                    dst_ip
                                )

                            self.flow_active[flow_key] = False
                            self.flow_stable_counts[flow_key] = 0
def launch():
    core.registerNew(Controller)