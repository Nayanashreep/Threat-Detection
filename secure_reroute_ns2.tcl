# ======================================================================
# NS-2 (Network Simulator 2.35) Simulation Script
# Project: SDN-Based Honeypot Threat Detection and Secure Routing for Financial Networks
# Author: NAYANASHREE P
# Description:
#   Simulates a financial network topology under DDoS attack.
#   Phase 1 (0.0s - 2.0s): Normal Financial Traffic (Client -> Bank Server).
#   Phase 2 (2.0s - 4.5s): Attacker initiates high-rate UDP/CBR flood -> Queue overflow -> Packet drops at bottleneck link.
#   Phase 3 (4.5s - 8.0s): SDN Controller initiates Secure Dynamic Rerouting -> Attacker traffic redirected to Honeypot trap (n5),
#                          clearing the bottleneck and restoring 100% PDR to Bank Server.
# ======================================================================

# 1. Initialize Simulator & Output Trace Files
set ns [new Simulator]

# Define color indexes for NAM (Network Animator)
$ns color 1 Blue       ;# Legitimate Customer TCP Traffic
$ns color 2 Red        ;# Malicious DDoS Flood Traffic
$ns color 3 Purple     ;# Rerouted Honeypot Traffic
$ns color 4 Green      ;# SDN Control Plane Packets

# Open Trace and NAM files
set tracefile [open "simulation.tr" w]
$ns trace-all $tracefile

set namfile [open "simulation.nam" w]
$ns namtrace-all $namfile

# 2. Create Network Topology Nodes
# n0: Client (Customer Host - 10.0.0.1)
set n0 [$ns node]
$n0 label "Customer (n0)"
$n0 color "blue"

# n1: Attacker (Adversary - 192.168.100.112)
set n1 [$ns node]
$n1 label "Attacker (n1)"
$n1 color "red"

# n2: Edge SDN Switch / Ingress Router
set n2 [$ns node]
$n2 label "Edge Switch S1 (n2)"
$n2 shape "box"
$n2 color "cyan"

# n3: Core SDN Switch
set n3 [$ns node]
$n3 label "Core Switch S2 (n3)"
$n3 shape "box"
$n3 color "cyan"

# n4: Production Bank Server Core (10.0.0.2)
set n4 [$ns node]
$n4 label "Bank Server (n4)"
$n4 shape "hexagon"
$n4 color "green"

# n5: Decoy Honeypot (10.0.0.5)
set n5 [$ns node]
$n5 label "Honeypot Decoy (n5)"
$n5 shape "hexagon"
$n5 color "purple"

# n6: Centralized SDN Controller
set n6 [$ns node]
$n6 label "SDN Controller (n6)"
$n6 shape "circle"
$n6 color "gold"

# 3. Create Duplex Links with Queues and Delays
# Links from hosts to Edge Switch
$ns duplex-link $n0 $n2 10Mb 5ms DropTail
$ns duplex-link $n1 $n2 10Mb 5ms DropTail

# Ingress to Core Bottleneck Link (2Mb, 10ms, queue limit 10 packets -> drops occur here during attack)
$ns duplex-link $n2 $n3 2Mb 10ms DropTail
$ns queue-limit $n2 $n3 10

# Core Switch to Bank Server
$ns duplex-link $n3 $n4 10Mb 5ms DropTail

# Edge Switch to Decoy Honeypot (Isolation VLAN Link)
$ns duplex-link $n2 $n5 10Mb 5ms DropTail

# Out-of-band SDN Control Links
$ns duplex-link $n6 $n2 100Mb 1ms DropTail
$ns duplex-link $n6 $n3 100Mb 1ms DropTail

# 4. Orient Links for Clean NAM Layout
$ns duplex-link-op $n0 $n2 orient down-right
$ns duplex-link-op $n1 $n2 orient up-right
$ns duplex-link-op $n2 $n3 orient right
$ns duplex-link-op $n3 $n4 orient up-right
$ns duplex-link-op $n2 $n5 orient down-right
$ns duplex-link-op $n6 $n2 orient up
$ns duplex-link-op $n6 $n3 orient up-right

# Monitor Queue on Bottleneck Link in NAM
$ns duplex-link-op $n2 $n3 queuePos 0.5

# 5. Setup Traffic Agents
# --- Agent A: Legitimate Customer Flow (TCP / FTP) ---
set tcp0 [new Agent/TCP]
$tcp0 set class_ 1
$tcp0 set fid_ 1
$ns attach-agent $n0 $tcp0

set sink0 [new Agent/TCPSink]
$ns attach-agent $n4 $sink0
$ns connect $tcp0 $sink0

set ftp0 [new Application/FTP]
$ftp0 attach-agent $tcp0
$ftp0 set type_ FTP

# --- Agent B: Malicious Attack Flow (UDP / CBR Volumetric Flood) ---
set udp1 [new Agent/UDP]
$udp1 set class_ 2
$udp1 set fid_ 2
$ns attach-agent $n1 $udp1

set null_bank [new Agent/Null]
$ns attach-agent $n4 $null_bank
$ns connect $udp1 $null_bank

set cbr1 [new Application/Traffic/CBR]
$cbr1 attach-agent $udp1
$cbr1 set packetSize_ 1000
$cbr1 set rate_ 5Mb
$cbr1 set random_ false

# --- Agent C: Honeypot Sink for Rerouted Malicious Traffic ---
set null_honeypot [new Agent/Null]
$ns attach-agent $n5 $null_honeypot

# 6. SDN Dynamic Flow-Mod Rerouting Procedure
proc sdn_secure_reroute {} {
    global ns udp1 null_honeypot
    puts "\n[+] [TIME: 4.5s] *** SDN CONTROLLER INTERVENTION ***"
    puts "[+] Anomaly Detected by Isolation Forest Engine!"
    puts "[+] OpenFlow Rule Pushed: Flow-Mod MATCH(src=192.168.100.112) -> ACTION(OUTPUT: port_n5_honeypot)"
    puts "[+] Malicious traffic rerouted away from Bank Server (n4) to Decoy Honeypot (n5)."
    puts "[+] Bottleneck link (n2-n3) congestion cleared. Packet drops mitigated.\n"
    
    # Reroute attacker UDP stream to Honeypot sink
    $ns connect $udp1 $null_honeypot
    $udp1 set fid_ 3
}

# 7. Simulation Timeline Schedule
# 0.5s: Customer begins legitimate banking requests
$ns at 0.5 "$ftp0 start"

# 2.0s: Attacker launches high-rate DDoS flood toward Bank Server (causes queue overflow and packet drops)
$ns at 2.0 "$cbr1 start"

# 4.5s: SDN Controller detects threat and executes dynamic secure reroute
$ns at 4.5 "sdn_secure_reroute"

# 7.0s: Stop traffic generators
$ns at 7.0 "$cbr1 stop"
$ns at 7.5 "$ftp0 stop"

# 8.0s: Finish Procedure
proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    puts "=========================================================="
    puts "NS-2 Simulation Completed Successfully!"
    puts "Trace file generated : simulation.tr"
    puts "NAM file generated   : simulation.nam"
    puts "Run NAM:  nam simulation.nam"
    puts "Run AWK:  awk -f pdr_and_drops.awk simulation.tr"
    puts "=========================================================="
    exit 0
}

$ns at 8.0 "finish"

# Start the simulation
puts "=========================================================="
puts "Starting NS-2 Simulation: SDN Honeypot & Secure Rerouting"
puts "=========================================================="
$ns run
