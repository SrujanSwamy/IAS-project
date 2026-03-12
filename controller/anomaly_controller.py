import math
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
import math
import csv
import time
import os

class AnomalyDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnomalyDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        # ADDED: Dictionaries to store the previous polling cycle's packet counts
        self.prev_src_counts = {}
        self.prev_dst_counts = {}

        self.metrics_file = 'evaluation/metrics.csv'
        os.makedirs(os.path.dirname(self.metrics_file), exist_ok=True)
        with open(self.metrics_file, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'FlowRate', 'Entropy'])
        
        self.monitor_thread = hub.spawn(self._monitor)

    def calculate_entropy(self, traffic_dict):
        """ Calculates normalized Shannon entropy for a given set of traffic data. """
        # Filter out negative or zero values just in case
        valid_counts = [count for count in traffic_dict.values() if count > 0]
        total_packets = sum(valid_counts)
        
        if total_packets == 0:
            return 0.0
        
        entropy = 0.0
        for count in valid_counts:
            probability = count / total_packets
            entropy -= probability * math.log2(probability)
        
        num_unique_elements = len(valid_counts)
        if num_unique_elements > 1:
            normalized_entropy = entropy / math.log2(num_unique_elements)
        else:
            normalized_entropy = 0.0
            
        return normalized_entropy

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        current_src_counts = {}
        current_dst_counts = {}

        # Gather the CURRENT total packet counts
        for stat in [flow for flow in body if flow.priority == 1]:
            src = stat.match.get('eth_src')
            dst = stat.match.get('eth_dst')
            packets = stat.packet_count
            
            if src:
                current_src_counts[src] = current_src_counts.get(src, 0) + packets
            if dst:
                current_dst_counts[dst] = current_dst_counts.get(dst, 0) + packets

        # Calculate the DELTA (traffic strictly within the last 5 seconds)
        window_src_counts = {}
        for mac, count in current_src_counts.items():
            prev_count = self.prev_src_counts.get(mac, 0)
            window_src_counts[mac] = max(0, count - prev_count)

        window_dst_counts = {}
        for mac, count in current_dst_counts.items():
            prev_count = self.prev_dst_counts.get(mac, 0)
            window_dst_counts[mac] = max(0, count - prev_count)

        #  Save current totals for the next 5-second polling cycle
        self.prev_src_counts = current_src_counts
        self.prev_dst_counts = current_dst_counts

        # Calculate Entropy using ONLY the 5-second window data
        src_entropy = self.calculate_entropy(window_src_counts)
        dst_entropy = self.calculate_entropy(window_dst_counts)

        self.logger.info("--- 5-Second Window Metrics ---")
        self.logger.info("Source MAC Entropy: %.3f | Dest MAC Entropy: %.3f", src_entropy, dst_entropy)
        self.logger.info("Total Packets in window: %d", sum(window_dst_counts.values()))

        flow_rate = sum(window_src_counts.values()) / 5.0

        with open(self.metrics_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([time.time(), flow_rate, dst_entropy])        

        # Anomaly Detection & Heavy Hitter Identification
        if sum(window_dst_counts.values()) > 50: 
            if dst_entropy < 0.3:
                attacker_mac = max(window_src_counts, key=window_src_counts.get)
                attack_volume = window_src_counts[attacker_mac]
                victim_mac = max(window_dst_counts, key=window_dst_counts.get)

                self.logger.warning("!!! ALERT: ANOMALY DETECTED !!!")
                self.logger.warning("Reason: Sudden drop in Destination Entropy (%.3f)", dst_entropy)
                self.logger.warning("--> VICTIM IDENTIFIED: %s", victim_mac)
                self.logger.warning("--> ATTACKER IDENTIFIED: %s (Window Volume: %d pkts)", attacker_mac, attack_volume)
        self.logger.info("-" * 32)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("--> Switch %s connected. Anomaly Detection Engine Online.", datapath.id)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return 

        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
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