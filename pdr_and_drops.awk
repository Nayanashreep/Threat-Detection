# ======================================================================
# AWK Post-Processing Script for NS-2 Trace File Analysis
# Calculates: Packet Delivery Ratio (PDR), Total Drops, Throughput & Delay
# Usage: awk -f pdr_and_drops.awk simulation.tr
# ======================================================================

BEGIN {
    sent_packets = 0;
    received_packets = 0;
    dropped_packets = 0;
    start_time = 9999999;
    end_time = 0;
    total_bytes_received = 0;
}

{
    event = $1;
    time = $2;
    from_node = $3;
    to_node = $4;
    pkt_type = $5;
    pkt_size = $6;
    flow_id = $8;
    src = $9;
    dst = $10;
    seq_num = $11;
    pkt_id = $12;

    if (time < start_time) start_time = time;
    if (time > end_time) end_time = time;

    # Track Enqueued Packets (Sent)
    if (event == "+" && (from_node == 0 || from_node == 1)) {
        sent_packets++;
    }

    # Track Dropped Packets
    if (event == "d") {
        dropped_packets++;
        drop_by_node[from_node]++;
        drop_by_flow[flow_id]++;
    }

    # Track Received Packets at Destination (Bank Server node 4 or Honeypot node 5)
    if (event == "r" && (to_node == 4 || to_node == 5)) {
        received_packets++;
        total_bytes_received += pkt_size;
    }
}

END {
    duration = end_time - start_time;
    pdr = (sent_packets > 0) ? (received_packets / sent_packets) * 100 : 0;
    throughput_kbps = (duration > 0) ? (total_bytes_received * 8) / (duration * 1000) : 0;

    print "==========================================================";
    print "           NS-2 SIMULATION ANALYSIS REPORT                ";
    print "==========================================================";
    printf "Simulation Duration           : %.2f seconds\n", duration;
    printf "Total Packets Generated       : %d\n", sent_packets;
    printf "Total Packets Received        : %d\n", received_packets;
    printf "Total Packets Dropped (d)     : %d\n", dropped_packets;
    printf "Packet Delivery Ratio (PDR)   : %.2f %%\n", pdr;
    printf "Average Network Throughput    : %.2f Kbps\n", throughput_kbps;
    print "----------------------------------------------------------";
    print "Breakdown of Drops by Bottleneck Switch Node:";
    for (node in drop_by_node) {
        printf "  Node %s Dropped: %d packets\n", node, drop_by_node[node];
    }
    print "==========================================================";
}
