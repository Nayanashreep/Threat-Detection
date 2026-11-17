# ======================================================================
# NS-2 Trace Generator & Simulation Engine for SDN Honeypot & Secure Rerouting
# Generates valid NS-2 Trace format (.tr) and NAM animation format (.nam)
# ======================================================================

import os
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRACE_FILE = os.path.join(BASE_DIR, "simulation.tr")
NAM_FILE = os.path.join(BASE_DIR, "simulation.nam")
TCL_FILE = os.path.join(BASE_DIR, "secure_reroute_ns2.tcl")
AWK_FILE = os.path.join(BASE_DIR, "pdr_and_drops.awk")

def run_discrete_ns2_simulation(duration=8.0, attack_start=2.0, reroute_start=4.5):
    """
    Simulates packet-by-packet events matching NS-2 trace format:
    Columns: [event, time, from_node, to_node, pkt_type, pkt_size, flags, fid, src_addr, dst_addr, seq_num, pkt_id]
    Events: '+' (enqueue), '-' (dequeue), 'r' (receive), 'd' (drop)
    """
    events = []
    trace_lines = []
    nam_lines = []

    # Node mappings:
    # 0: Customer (10.0.0.1)
    # 1: Attacker (192.168.100.112)
    # 2: Edge Switch S1
    # 3: Core Switch S2
    # 4: Bank Server (10.0.0.2)
    # 5: Honeypot Decoy (10.0.0.5)

    nam_lines.append("V -t * -v 1.0a5 -a 0")
    nam_lines.append("W -t * -x 800 -y 400")
    nam_lines.append("n -t * -s 0 -S DORMANT -c blue -i blue -a 0 -o 0.0.0.0 -v circle -l \"Customer(n0)\"")
    nam_lines.append("n -t * -s 1 -S DORMANT -c red -i red -a 1 -o 1.0.0.0 -v circle -l \"Attacker(n1)\"")
    nam_lines.append("n -t * -s 2 -S DORMANT -c cyan -i cyan -a 2 -o 2.0.0.0 -v box -l \"EdgeSwitch(n2)\"")
    nam_lines.append("n -t * -s 3 -S DORMANT -c cyan -i cyan -a 3 -o 3.0.0.0 -v box -l \"CoreSwitch(n3)\"")
    nam_lines.append("n -t * -s 4 -S DORMANT -c green -i green -a 4 -o 4.0.0.0 -v hexagon -l \"BankServer(n4)\"")
    nam_lines.append("n -t * -s 5 -S DORMANT -c purple -i purple -a 5 -o 5.0.0.0 -v hexagon -l \"Honeypot(n5)\"")
    nam_lines.append("l -t * -s 0 -d 2 -S UP -r 10Mb -D 5ms -c black")
    nam_lines.append("l -t * -s 1 -d 2 -S UP -r 10Mb -D 5ms -c black")
    nam_lines.append("l -t * -s 2 -d 3 -S UP -r 2Mb -D 10ms -c black")
    nam_lines.append("l -t * -s 3 -d 4 -S UP -r 10Mb -D 5ms -c black")
    nam_lines.append("l -t * -s 2 -d 5 -S UP -r 10Mb -D 5ms -c black")

    pkt_id = 0
    seq_customer = 0
    seq_attacker = 0

    stats = {
        "sent_customer": 0,
        "sent_attacker": 0,
        "delivered_bank": 0,
        "delivered_honeypot": 0,
        "dropped_packets": 0,
        "pdr_customer": 100.0,
        "pdr_overall": 100.0,
        "active_phase": "NORMAL",
        "drop_events": []
    }

    t = 0.5
    queue_bottleneck = 0
    MAX_QUEUE = 10

    while t < duration:
        t += random.uniform(0.015, 0.035)
        phase = "NORMAL"
        if t >= reroute_start:
            phase = "SECURE_REROUTE"
        elif t >= attack_start:
            phase = "DDOS_ATTACK"

        # 1. Customer Traffic Generation (Consistent legitimate banking requests)
        pkt_id += 1
        seq_customer += 1
        stats["sent_customer"] += 1
        c_time = round(t, 4)

        # Enqueue customer packet n0 -> n2
        trace_lines.append(f"+ {c_time:.6f} 0 2 tcp 512 ------- 1 0.0 4.0 {seq_customer} {pkt_id}")
        trace_lines.append(f"- {c_time + 0.001:.6f} 0 2 tcp 512 ------- 1 0.0 4.0 {seq_customer} {pkt_id}")
        trace_lines.append(f"r {c_time + 0.006:.6f} 0 2 tcp 512 ------- 1 0.0 4.0 {seq_customer} {pkt_id}")

        if phase == "DDOS_ATTACK" and queue_bottleneck >= MAX_QUEUE and random.random() < 0.65:
            # Customer packet gets victimized by attack congestion
            stats["dropped_packets"] += 1
            drop_time = round(c_time + 0.007, 4)
            trace_lines.append(f"d {drop_time:.6f} 2 3 tcp 512 ------- 1 0.0 4.0 {seq_customer} {pkt_id}")
            events.append({
                "time": drop_time,
                "event": "d",
                "type": "tcp",
                "from": 2,
                "to": 3,
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "fid": 1,
                "desc": "Customer packet DROPPED due to bottleneck buffer overflow!"
            })
            stats["drop_events"].append({"time": drop_time, "pkt_id": pkt_id, "src": "10.0.0.1", "victim": True})
        else:
            # Reaches bank
            stats["delivered_bank"] += 1
            arr_time = round(c_time + 0.021, 4)
            trace_lines.append(f"+ {c_time + 0.007:.6f} 2 3 tcp 512 ------- 1 0.0 4.0 {seq_customer} {pkt_id}")
            trace_lines.append(f"r {c_time + 0.017:.6f} 2 3 tcp 512 ------- 1 0.0 4.0 {seq_customer} {pkt_id}")
            trace_lines.append(f"r {arr_time:.6f} 3 4 tcp 512 ------- 1 0.0 4.0 {seq_customer} {pkt_id}")
            events.append({
                "time": arr_time,
                "event": "r",
                "type": "tcp",
                "from": 3,
                "to": 4,
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "fid": 1,
                "desc": "Customer packet delivered safely to Bank Server"
            })

        # 2. Attacker Traffic Generation (Burst mode when attack is active)
        if phase in ["DDOS_ATTACK", "SECURE_REROUTE"]:
            flood_rate = 5 if phase == "DDOS_ATTACK" else 3
            for _ in range(flood_rate):
                pkt_id += 1
                seq_attacker += 1
                stats["sent_attacker"] += 1
                a_time = round(t + random.uniform(0.001, 0.008), 4)

                # Attacker sends UDP/CBR packet
                trace_lines.append(f"+ {a_time:.6f} 1 2 cbr 1000 ------- 2 1.0 4.0 {seq_attacker} {pkt_id}")
                trace_lines.append(f"- {a_time + 0.001:.6f} 1 2 cbr 1000 ------- 2 1.0 4.0 {seq_attacker} {pkt_id}")
                trace_lines.append(f"r {a_time + 0.005:.6f} 1 2 cbr 1000 ------- 2 1.0 4.0 {seq_attacker} {pkt_id}")

                if phase == "DDOS_ATTACK":
                    queue_bottleneck += 1
                    if queue_bottleneck > MAX_QUEUE:
                        # Drop packet at Edge Switch n2
                        stats["dropped_packets"] += 1
                        drop_time = round(a_time + 0.006, 4)
                        trace_lines.append(f"d {drop_time:.6f} 2 3 cbr 1000 ------- 2 1.0 4.0 {seq_attacker} {pkt_id}")
                        events.append({
                            "time": drop_time,
                            "event": "d",
                            "type": "cbr",
                            "from": 2,
                            "to": 3,
                            "src": "192.168.100.112",
                            "dst": "10.0.0.2",
                            "fid": 2,
                            "desc": f"DDoS Packet #{pkt_id} DROPPED (Queue Limit Exceeded: {queue_bottleneck}/{MAX_QUEUE})"
                        })
                        stats["drop_events"].append({"time": drop_time, "pkt_id": pkt_id, "src": "192.168.100.112", "victim": False})
                        queue_bottleneck = MAX_QUEUE
                    else:
                        # Malicious packet floods Bank Server
                        trace_lines.append(f"+ {a_time + 0.006:.6f} 2 3 cbr 1000 ------- 2 1.0 4.0 {seq_attacker} {pkt_id}")
                        trace_lines.append(f"r {a_time + 0.020:.6f} 3 4 cbr 1000 ------- 2 1.0 4.0 {seq_attacker} {pkt_id}")
                        events.append({
                            "time": round(a_time + 0.020, 4),
                            "event": "r",
                            "type": "cbr",
                            "from": 3,
                            "to": 4,
                            "src": "192.168.100.112",
                            "dst": "10.0.0.2",
                            "fid": 2,
                            "desc": "Malicious Flood Packet reached Bank Server (Congestion High!)"
                        })
                elif phase == "SECURE_REROUTE":
                    # SDN Controller Reroute -> Diverted to Honeypot (n5)
                    queue_bottleneck = max(0, queue_bottleneck - 2)
                    arr_time = round(a_time + 0.009, 4)
                    trace_lines.append(f"+ {a_time + 0.006:.6f} 2 5 cbr 1000 ------- 3 1.0 5.0 {seq_attacker} {pkt_id}")
                    trace_lines.append(f"r {arr_time:.6f} 2 5 cbr 1000 ------- 3 1.0 5.0 {seq_attacker} {pkt_id}")
                    stats["delivered_honeypot"] += 1
                    events.append({
                        "time": arr_time,
                        "event": "r",
                        "type": "cbr",
                        "from": 2,
                        "to": 5,
                        "src": "192.168.100.112",
                        "dst": "10.0.0.5",
                        "fid": 3,
                        "desc": "Malicious packet REROUTED into Decoy Honeypot (n5) ✓"
                    })

    # Calculate overall metrics
    total_sent = stats["sent_customer"] + stats["sent_attacker"]
    total_delivered = stats["delivered_bank"] + stats["delivered_honeypot"]
    stats["total_sent"] = total_sent
    stats["total_delivered"] = total_delivered
    stats["pdr_customer"] = round((stats["delivered_bank"] / max(1, stats["sent_customer"])) * 100, 2)
    stats["pdr_overall"] = round((total_delivered / max(1, total_sent)) * 100, 2)
    stats["throughput_kbps"] = round((total_delivered * 1000 * 8) / (duration * 1000), 2)

    # Save to simulation.tr and simulation.nam
    try:
        with open(TRACE_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(trace_lines) + "\n")
        with open(NAM_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(nam_lines) + "\n")
    except Exception as e:
        print(f"[!] Warning: Failed to write trace files: {e}")

    return {
        "stats": stats,
        "recent_events": events[-100:],
        "sample_trace_lines": trace_lines[-50:],
        "files": {
            "tcl": "secure_reroute_ns2.tcl",
            "tr": "simulation.tr",
            "nam": "simulation.nam",
            "awk": "pdr_and_drops.awk"
        }
    }
