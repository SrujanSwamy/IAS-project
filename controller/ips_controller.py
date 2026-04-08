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
        self.history_entropies = []
        self.history_hh_ratios = []
        self.MIN_HISTORY_SAMPLES = 5
        self.HISTORY_WINDOW = 20
        self.blocked_macs = set()
        self.strike_counter = {} # NEW: Tracks how many times a MAC has offended

        # Unified detection constants
        self.MIN_RATE_FLOOR = 50
        self.MIN_ENTROPY_FLOOR = 0.05
        self.MIN_HH_RATIO = 0.35

        # OpenFlow metering state for progressive mitigation
        self.mac_meter_ids = {}
        self.next_meter_id = 1

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
        """Evaluates sFlow volume every 5 seconds. Only polls OpenFlow if volume spikes OR if baseline is missing."""
        while True:
            hub.sleep(5)
            estimated_rate = (self.sflow_sample_count * 64) / 5.0
            self.sflow_sample_count = 0 

            # WAKE UP OpenFlow if traffic spikes OR if we still need to build the baseline history!
            if estimated_rate > 100 or len(self.history_rates) < self.MIN_HISTORY_SAMPLES:
                if estimated_rate > 100:
                    self.logger.info("📈 sFlow detected traffic spike (Estimated Rate: %.2f). Waking up OpenFlow inspector...", estimated_rate)
                else:
                    self.logger.info("⚙️ Gathering baseline data... Waking up OpenFlow temporarily.")
                
                for dp in self.datapaths.values():
                    self._request_stats(dp)
            else:
                # True Peacetime logging - Baseline is full and traffic is low!
                self.logger.info("💤 sFlow Peacetime (Estimated Rate: %.2f). OpenFlow polling paused to save CPU.", estimated_rate)
                
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

    def _ensure_meter(self, datapath, attacker_mac, kbps_rate):
        """Creates/updates a DROP meter used for rate limiting attacker traffic."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if attacker_mac not in self.mac_meter_ids:
            self.mac_meter_ids[attacker_mac] = self.next_meter_id
            self.next_meter_id += 1

        meter_id = self.mac_meter_ids[attacker_mac]
        flags = ofproto.OFPMF_KBPS
        band = parser.OFPMeterBandDrop(rate=max(1, int(kbps_rate)), burst_size=max(1, int(kbps_rate / 4)))

        # Delete first so updates are idempotent on OVS.
        del_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_DELETE,
            flags=flags,
            meter_id=meter_id,
            bands=[]
        )
        datapath.send_msg(del_mod)

        add_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=flags,
            meter_id=meter_id,
            bands=[band]
        )
        datapath.send_msg(add_mod)
        return meter_id

    def _apply_rate_limit(self, datapath, attacker_mac, kbps_rate=1000, timeout=60):
        """Installs a high-priority metered rule for attacker traffic as strike-1 mitigation."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        meter_id = self._ensure_meter(datapath, attacker_mac, kbps_rate)

        match = parser.OFPMatch(eth_src=attacker_mac)
        inst = [
            parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER),
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=90,
            match=match,
            instructions=inst,
            hard_timeout=timeout
        )
        datapath.send_msg(mod)
        self.logger.warning("🛡️ STRIKE 1: Rate limiting %s with meter %d at %d kbps for %d seconds.",
                            attacker_mac, meter_id, int(kbps_rate), timeout)

    def mitigate_attack(self, datapath, attacker_mac):
        """Implements a 3-Strike Progressive Penalty System."""
        if attacker_mac in self.blocked_macs: 
            return # Already actively blocked or throttled
            
        # Increment their strike count (defaults to 0 if first offense, then adds 1)
        self.strike_counter[attacker_mac] = self.strike_counter.get(attacker_mac, 0) + 1
        strikes = self.strike_counter[attacker_mac]
            
        if strikes == 1:
            # Strike-1: Throttle traffic to 1000 kbps for 60 seconds
            self._apply_rate_limit(datapath, attacker_mac, kbps_rate=1000, timeout=60)
            
            # FIX: Mark them as blocked and start the 60s countdown!
            self.blocked_macs.add(attacker_mac)
            hub.spawn_after(60, self.unblock_mac, attacker_mac)
            return

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
            # ⚔️ STRIKE 2: Temporary 60-second penalty drop
            mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst, hard_timeout=60)
            datapath.send_msg(mod)
            self.blocked_macs.add(attacker_mac)
            self.logger.warning("⚔️ STRIKE 2: Dropping traffic from %s for 60 seconds.", attacker_mac)
            
            # Start the timer to forgive them
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
        total_src_packets = sum(window_src_counts.values())

        attacker_mac = None
        attacker_pkts = 0
        hh_ratio = 0.0
        if total_src_packets > 0 and window_src_counts:
            attacker_mac = max(window_src_counts, key=window_src_counts.get)
            attacker_pkts = window_src_counts[attacker_mac]
            hh_ratio = attacker_pkts / float(total_src_packets)

        with open(self.metrics_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([time.time(), flow_rate, dst_entropy])        

        self.logger.info("--- Deep OpenFlow Inspection ---")
        self.logger.info("Exact Flow Rate: %.2f pkts/sec | Dest Entropy: %.3f | HH Ratio: %.2f",
                         flow_rate, dst_entropy, hh_ratio)

        is_anomaly = False

        enough_rate = len(self.history_rates) >= self.MIN_HISTORY_SAMPLES
        enough_entropy = len(self.history_entropies) >= self.MIN_HISTORY_SAMPLES
        enough_hh = len(self.history_hh_ratios) >= self.MIN_HISTORY_SAMPLES

        if enough_rate and enough_entropy and enough_hh:
            mean_rate = statistics.mean(self.history_rates)
            std_rate = statistics.stdev(self.history_rates) if len(self.history_rates) > 1 else 0.0
            dynamic_rate_threshold = max(self.MIN_RATE_FLOOR, mean_rate + (3 * std_rate))

            mean_entropy = statistics.mean(self.history_entropies)
            std_entropy = statistics.stdev(self.history_entropies) if len(self.history_entropies) > 1 else 0.0
            dynamic_entropy_floor = max(self.MIN_ENTROPY_FLOOR, mean_entropy - (2 * std_entropy))

            mean_hh = statistics.mean(self.history_hh_ratios)
            std_hh = statistics.stdev(self.history_hh_ratios) if len(self.history_hh_ratios) > 1 else 0.0
            dynamic_hh_threshold = min(0.95, max(self.MIN_HH_RATIO, mean_hh + (2 * std_hh)))
            
            self.logger.info(
                "Dynamic Thresholds -> Rate: %.2f (mu=%.2f, sigma=%.2f) | Entropy Floor: %.3f (mu=%.3f, sigma=%.3f) | HH Ratio: %.2f (mu=%.2f, sigma=%.2f)",
                dynamic_rate_threshold, mean_rate, std_rate,
                dynamic_entropy_floor, mean_entropy, std_entropy,
                dynamic_hh_threshold, mean_hh, std_hh
            )

            # Unified adaptive rule: spike + entropy collapse + dominant heavy hitter.
            if (
                attacker_mac is not None
                and flow_rate > dynamic_rate_threshold
                and dst_entropy < dynamic_entropy_floor
                and hh_ratio > dynamic_hh_threshold
            ):
                is_anomaly = True
                self.logger.warning(
                    "🚨 ADAPTIVE ANOMALY DETECTED! Rate %.2f > %.2f, Entropy %.3f < %.3f, HH %.2f > %.2f",
                    flow_rate, dynamic_rate_threshold, dst_entropy, dynamic_entropy_floor, hh_ratio, dynamic_hh_threshold
                )
                self.logger.warning("--> ATTACKER IDENTIFIED: %s (window packets: %d)", attacker_mac, attacker_pkts)
                self.mitigate_attack(datapath, attacker_mac)
        else:
            self.logger.info(
                "Gathering baseline... rate=%d/%d entropy=%d/%d hh=%d/%d",
                len(self.history_rates), self.MIN_HISTORY_SAMPLES,
                len(self.history_entropies), self.MIN_HISTORY_SAMPLES,
                len(self.history_hh_ratios), self.MIN_HISTORY_SAMPLES
            )

        if not is_anomaly:
            self.history_rates.append(flow_rate)
            self.history_entropies.append(dst_entropy)
            self.history_hh_ratios.append(hh_ratio)

            if len(self.history_rates) > self.HISTORY_WINDOW:
                self.history_rates.pop(0)
            if len(self.history_entropies) > self.HISTORY_WINDOW:
                self.history_entropies.pop(0)
            if len(self.history_hh_ratios) > self.HISTORY_WINDOW:
                self.history_hh_ratios.pop(0)

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