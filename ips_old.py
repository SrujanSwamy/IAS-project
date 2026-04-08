import math
import statistics
import csv
import time
import os
import socket
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub

class IPSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IPSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.prev_src_counts = {}
        self.prev_dst_counts = {}

        self.history_rates = []
        self.MIN_HISTORY_SAMPLES = 5
        self.blocked_macs = set()
        self.strike_counter = {} # NEW: Tracks how many times a MAC has offended

        self.metrics_file = 'evaluation/metrics.csv'
        os.makedirs(os.path.dirname(self.metrics_file), exist_ok=True)
        with open(self.metrics_file, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'FlowRate', 'Entropy'])
        
        # --- PHASE 2: sFlow UDP Listener Setup ---
        self.sflow_port = 6343
        self.sflow_sample_count = 0
        self.sflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sflow_sock.bind(('0.0.0.0', self.sflow_port))
        
        # Start the background threads
        self.sflow_listener_thread = hub.spawn(self._sflow_listener)
        self.sflow_evaluator_thread = hub.spawn(self._sflow_evaluator)

    def calculate_entropy(self, traffic_dict):
        valid_counts = [count for count in traffic_dict.values() if count > 0]
        total_packets = sum(valid_counts)
        if total_packets == 0: return 0.0
        entropy = sum([- (c / total_packets) * math.log2(c / total_packets) for c in valid_counts])
        n = len(valid_counts)
        return entropy / math.log2(n) if n > 1 else 0.0

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths: self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths: del self.datapaths[datapath.id]

    # --- NEW: Lightweight sFlow Listener ---
    def _sflow_listener(self):
        """Listens for sFlow UDP datagrams pushed by the switch."""
        self.logger.info("🎧 sFlow Telemetry Listener started on UDP port %d", self.sflow_port)
        while True:
            try:
                # We don't need to parse the heavy binary payload, just receiving it is enough to measure volume!
                data, addr = self.sflow_sock.recvfrom(2048)
                self.sflow_sample_count += 1
            except Exception as e:
                hub.sleep(0.1)

    # --- NEW: sFlow Evaluator (Replaces the heavy OpenFlow polling loop) ---
    def _sflow_evaluator(self):
        """Evaluates sFlow volume every 5 seconds. Only polls OpenFlow if volume spikes."""
        while True:
            hub.sleep(5)
            # Extrapolate flow rate: (Samples in 5s * 64 sampling rate) / 5 seconds
            estimated_rate = (self.sflow_sample_count * 64) / 5.0
            
            # Reset counter for the next window
            self.sflow_sample_count = 0 

            # If sFlow sees high traffic, wake up the heavy OpenFlow inspector
            if estimated_rate > 50:
                self.logger.info("📈 sFlow detected traffic spike (Estimated Rate: %.2f). Waking up OpenFlow inspector...", estimated_rate)
                for dp in self.datapaths.values():
                    self._request_stats(dp)
            else:
                # Peacetime logging - No OpenFlow overhead!
                self.logger.info("💤 sFlow Peacetime (Estimated Rate: %.2f). OpenFlow polling paused to save CPU.", estimated_rate)
                
                # Keep graph moving during peacetime
                with open(self.metrics_file, mode='a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([time.time(), estimated_rate, 1.0])

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def unblock_mac(self, mac):
        """Removes the MAC from the blocked list after the hardware timeout expires."""
        if mac in self.blocked_macs:
            self.blocked_macs.remove(mac)
            self.logger.info("🔓 TIMEOUT EXPIRED: MAC %s has been unblocked by the controller.", mac)

    def mitigate_attack(self, datapath, attacker_mac):
        """Implements a 3-Strike Progressive Penalty System."""
        if attacker_mac in self.blocked_macs: 
            return # Already actively blocked
            
        # Increment their strike count (defaults to 0 if first offense, then adds 1)
        self.strike_counter[attacker_mac] = self.strike_counter.get(attacker_mac, 0) + 1
        strikes = self.strike_counter[attacker_mac]
            
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=attacker_mac)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        
        if strikes >= 3:
            # ☠️ STRIKE 3: Permanent Ban (No hard_timeout)
            mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst)
            datapath.send_msg(mod)
            self.blocked_macs.add(attacker_mac)
            self.logger.error("☠️ STRIKE 3! PERMANENT BAN: Blocklisted MAC %s indefinitely.", attacker_mac)
        else:
            # ⚔️ STRIKE 1 & 2: Temporary 60-second penalty
            mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst, hard_timeout=60)
            datapath.send_msg(mod)
            self.blocked_macs.add(attacker_mac)
            self.logger.warning("⚔️ STRIKE %d: Dropping traffic from %s for 60 seconds.", strikes, attacker_mac)
            
            # Start the timer to forgive them (only for temporary bans)
            hub.spawn_after(60, self.unblock_mac, attacker_mac)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        current_src_counts = {}
        current_dst_counts = {}

        for stat in [flow for flow in body if flow.priority == 1]:
            src, dst, pkts = stat.match.get('eth_src'), stat.match.get('eth_dst'), stat.packet_count
            if src: current_src_counts[src] = current_src_counts.get(src, 0) + pkts
            if dst: current_dst_counts[dst] = current_dst_counts.get(dst, 0) + pkts

        window_src_counts = {mac: max(0, count - self.prev_src_counts.get(mac, 0)) for mac, count in current_src_counts.items()}
        window_dst_counts = {mac: max(0, count - self.prev_dst_counts.get(mac, 0)) for mac, count in current_dst_counts.items()}

        self.prev_src_counts = current_src_counts
        self.prev_dst_counts = current_dst_counts

        dst_entropy = self.calculate_entropy(window_dst_counts)
        flow_rate = sum(window_src_counts.values()) / 5.0

        with open(self.metrics_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([time.time(), flow_rate, dst_entropy])        

        self.logger.info("--- Deep OpenFlow Inspection ---")
        self.logger.info("Exact Flow Rate: %.2f pkts/sec | Dest Entropy: %.3f", flow_rate, dst_entropy)

        is_anomaly = False

        if len(self.history_rates) >= self.MIN_HISTORY_SAMPLES:
            mean_rate = statistics.mean(self.history_rates)
            std_dev = statistics.stdev(self.history_rates) if len(self.history_rates) > 1 else 0
            dynamic_threshold = max(50, mean_rate + (3 * std_dev))
            
            self.logger.info("Dynamic Threshold: %.2f (Mean: %.2f, StdDev: %.2f)", dynamic_threshold, mean_rate, std_dev)

            if flow_rate > dynamic_threshold and dst_entropy < 0.3:
                is_anomaly = True
                attacker_mac = max(window_src_counts, key=window_src_counts.get)
                self.logger.warning("🚨 ADAPTIVE ANOMALY DETECTED! Rate (%.2f) breached threshold (%.2f)", flow_rate, dynamic_threshold)
                self.logger.warning("--> ATTACKER IDENTIFIED: %s", attacker_mac)
                self.mitigate_attack(datapath, attacker_mac)
        else:
            self.logger.info("Gathering baseline... (%d/%d)", len(self.history_rates), self.MIN_HISTORY_SAMPLES)

        if not is_anomaly:
            self.history_rates.append(flow_rate)
            if len(self.history_rates) > 10: self.history_rates.pop(0)

        self.logger.info("-" * 32)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("--> Switch %s connected. Hybrid Telemetry IPS Online.", datapath.id)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id: mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else: mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
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

        if eth.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]: return 

        dst, src = eth.dst, eth.src
        dpid = format(datapath.id, "d").zfill(16)
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
                
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)