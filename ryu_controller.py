from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

app_name = 'financial_sdn_app'
url = '/block'

class SDNBlockerController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SDNBlockerController, self).__init__(req, link, data, **config)
        self.sdn_app = data[app_name]

    @route('block', url, methods=['POST'])
    def block_ip_api(self, req, **kwargs):
        sdn_app = self.sdn_app
        try:
            body = json.loads(req.body.decode('utf-8'))
            target_ip = body.get('ip')
            if not target_ip:
                return Response(status=400, body='Missing "ip" parameter')
            
            # Send flow mod to all registered switches
            sdn_app.block_ip(target_ip)
            return Response(status=200, body=f'IP {target_ip} blocked successfully on all switches.')
        except Exception as e:
            return Response(status=500, body=str(e))

class FinancialSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(FinancialSDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        wsgi = kwargs['wsgi']
        wsgi.register(SDNBlockerController, {app_name: self})
        self.logger.info("Financial SDN Controller Initialized with REST API on port 8080")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info(f"Switch connected: {datapath.id}")
                self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            pass # not used yet

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Installed table-miss flow on switch {datapath.id}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def block_ip(self, ip_address):
        """Block an IP address on all switches."""
        self.logger.info(f"Received API command to block IP: {ip_address}")
        for dp_id, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Match packets coming from this IP
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
            
            # Empty actions means DROP
            actions = []
            
            self.add_flow(datapath, 100, match, actions)
            self.logger.info(f"Added DROP flow for {ip_address} on switch {dp_id}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Basic L2 switching
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to avoid packet-in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
