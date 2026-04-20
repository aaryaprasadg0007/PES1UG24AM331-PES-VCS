"""
SDN Packet Logger & Dynamic Firewall — Ryu + OpenFlow 1.3
==========================================================
Features:
  • Capture packet headers & extract deep metrics
  • DYNAMIC FIREWALL: Blocks based on MAC, IP, or Port
  • Logs explicit block reasons to console dynamically
"""

import logging
import os
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, udp, icmp, ether_types

# ── Logging setup ─────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

# (We are keeping this for Ryu's internal errors, but our custom logs go to firewall_logs.txt)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    handlers=[
        logging.FileHandler("logs/packets.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("PacketLogger")

# ── Firewall Configuration ────────────────────────────────────────────────────
# Edit these values to demonstrate blocking to your teacher
BLOCKED_MAC = "00:00:00:00:00:03"  # Block specific MAC (e.g., h3)
BLOCKED_IP  = "10.0.0.3"           # Block specific IP (e.g., h3)
BLOCKED_PORT = 8080                # Block specific TCP/UDP Port

class PacketLogger(app_manager.RyuApp):
    """Simple SDN packet logger: capture, identify, log, display, and dynamic firewall."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.packet_count = 0
       
        self.mac_table = {}  # {(dpid, mac): port} for L2 forwarding

    # ── Custom Instant Log Writer ─────────────────────────────────────────────
    def write_log(self, message):
        """Prints to the terminal AND instantly appends to the log file."""
        print(message)
        with open("sdn_traffic.txt", "a") as log_file:
            log_file.write(message + "\n")
    # ──────────────────────────────────────────────────────────────────────────

    # ── Switch connects: install rules ────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp      = ev.msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser

        # 1. Table-miss (Priority 0): send every new packet to the controller
        match_miss   = parser.OFPMatch()
        actions_miss = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst_miss    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions_miss)]
        mod_miss = parser.OFPFlowMod(
            datapath=dp, priority=0, match=match_miss, instructions=inst_miss
        )
        dp.send_msg(mod_miss)
        
        # Switched to self.write_log to capture the startup sequence
        self.write_log(f"[SWITCH CONNECTED] dpid={dp.id}  OpenFlow 1.3 ready")
        self.write_log(f"[FIREWALL ACTIVE] Block Rules -> MAC: {BLOCKED_MAC} | IP: {BLOCKED_IP} | PORT: {BLOCKED_PORT}")
        self.write_log("-" * 80)

    # ── Packet-In: capture, parse, log, forward ───────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        in_port = msg.match["in_port"]

        self.packet_count += 1
        pkt  = packet.Packet(msg.data)
        
        # Pass msg.data so we can calculate the total packet size
        info = self._parse_packet(pkt, in_port, dp.id, msg.data)

        # ── 1. DYNAMIC FIREWALL LOGIC ─────────────────────────────────────────
       
        # Check MAC Address
        
        if info["eth_src"] == BLOCKED_MAC or info["eth_dst"] == BLOCKED_MAC:
            self._display(info, status="[MAC BLOCKED] ")
            return  # Drop packet by ignoring it (not forwarding)

        # Check IP Address
        if info["ip_src"] == BLOCKED_IP or info["ip_dst"] == BLOCKED_IP:
            self._display(info, status="[IP BLOCKED]  ")
            return  

        # Check Port (TCP or UDP)
        if info["src_port"] == BLOCKED_PORT or info["dst_port"] == BLOCKED_PORT:
            self._display(info, status="[PORT BLOCKED]")
            return  

        # If it passes the firewall, display as allowed
        self._display(info, status="[ALLOWED]     ")
        # ──────────────────────────────────────────────────────────────────────

        # ── L2 learning ───────────────────────────────────────────────────────
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth:
            self.mac_table[(dp.id, eth.src)] = in_port

        # ── Forward: unicast if dst known, else flood ─────────────────────────
        out_port = ofproto.OFPP_FLOOD
        if eth:
            known = self.mac_table.get((dp.id, eth.dst))
            if known:
                out_port = known

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow rule (Priority 10) so future packets skip the controller
        if out_port != ofproto.OFPP_FLOOD and eth:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            inst  = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                  actions)]
            mod = parser.OFPFlowMod(
                datapath=dp, priority=10, match=match, instructions=inst,
                idle_timeout=10, hard_timeout=30,
            )
            dp.send_msg(mod)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                return

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        dp.send_msg(out)

    # ── Parse packet headers ──────────────────────────────────────────────────
    def _parse_packet(self, pkt, in_port, dpid, raw_data):
        info = {
            "pkt_id":    self.packet_count,
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "dpid":      dpid,
            "in_port":   in_port,
            "total_len": len(raw_data),
            "protocols": [],
            "eth_src":   None, "eth_dst": None,
            "ip_src":    None, "ip_dst":  None, "ip_ttl": None,
            "src_port":  None, "dst_port": None,
            "tcp_flags": "",
            "icmp_type": None, "icmp_code": None,
            "arp_op":    None,
        }

        eth = pkt.get_protocol(ethernet.ethernet)
        if eth:
            info["protocols"].append("Ethernet")
            info["eth_src"] = eth.src
            info["eth_dst"] = eth.dst

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            info["protocols"].append("ARP")
            info["arp_op"] = "REQUEST" if arp_pkt.opcode == 1 else "REPLY"
            info["ip_src"] = arp_pkt.src_ip
            info["ip_dst"] = arp_pkt.dst_ip

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4:
            info["protocols"].append("IPv4")
            info["ip_src"] = ip4.src
            info["ip_dst"] = ip4.dst
            info["ip_ttl"] = ip4.ttl

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            info["protocols"].append("TCP")
            info["src_port"] = tcp_pkt.src_port
            info["dst_port"] = tcp_pkt.dst_port
            
            # Extract TCP Flags
            flags = []
            if tcp_pkt.has_flags(tcp.TCP_SYN): flags.append("SYN")
            if tcp_pkt.has_flags(tcp.TCP_ACK): flags.append("ACK")
            if tcp_pkt.has_flags(tcp.TCP_FIN): flags.append("FIN")
            if tcp_pkt.has_flags(tcp.TCP_RST): flags.append("RST")
            if tcp_pkt.has_flags(tcp.TCP_PSH): flags.append("PSH")
            if tcp_pkt.has_flags(tcp.TCP_URG): flags.append("URG")
            info["tcp_flags"] = "[" + ",".join(flags) + "]" if flags else ""

        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            info["protocols"].append("UDP")
            info["src_port"] = udp_pkt.src_port
            info["dst_port"] = udp_pkt.dst_port

        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt:
            info["protocols"].append("ICMP")
            info["icmp_type"] = icmp_pkt.type
            info["icmp_code"] = icmp_pkt.code

        return info

    # ── Display formatted packet info ─────────────────────────────────────────
    def _display(self, info, status=""):
        proto_str = " / ".join(info["protocols"]) or "Unknown"

        # Show MAC and IP address
        addr = ""
        if info["eth_src"]:
            addr += f"MAC: {info['eth_src']}→{info['eth_dst']}   "
        if info["ip_src"]:
            addr += f"IP: {info['ip_src']}→{info['ip_dst']}"
        if not addr:
            addr = "?"

        extra = ""
        if info["src_port"]:
            extra = f"  Port: {info['src_port']}→{info['dst_port']} {info['tcp_flags']}"
        elif info["arp_op"]:
            extra = f"  ARP {info['arp_op']}"
        elif info["icmp_type"] is not None:
            extra = f"  ICMP type={info['icmp_type']}"

        # Switched to self.write_log to bypass buffer delays
        formatted_message = (
            f"{status} [PKT #{info['pkt_id']:05d}]  {info['timestamp']}  "
            f"Port:{info['in_port']}  {proto_str:<25}  {addr}{extra}  Size:{info['total_len']}B"
        )
        self.write_log(formatted_message)
