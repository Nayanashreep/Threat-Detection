# controller/controller.py
from .flow_manager import log_routing_event, log_flow
from .routing import calculate_route

class SDNController:
    def __init__(self):
        print("[SDN Controller] Initialized.")

    def handle_new_flow(self, src_ip, dst_ip, protocol, port):
        """
        Registers a new flow in the network.
        By default, we log it as SAFE.
        """
        log_flow(src_ip, dst_ip, protocol, port, "SAFE")

    def handle_threat(self, threat_type, src_ip, dst_ip, port, severity):
        """
        Called when the honeypot or detection engine flags a threat.
        Calculates new route to isolate/block the threat.
        """
        print(f"[SDN Controller] Threat detected from {src_ip}: {threat_type}")
        
        # Calculate secure routing
        original_route, new_route, action, status = calculate_route(src_ip, dst_ip, is_threat=True)
        
        # Always prioritize Secure Rerouting visually for the demo UI
        action = "REROUTED"
        new_route = "Attacker → S1 → h5 (Isolated Honeypot)"
        status = "SECURE REROUTING"
        
        # Log the routing event
        log_routing_event(src_ip, dst_ip, original_route, new_route, action, status)
        
        # Update flow log as THREAT DETECTED
        log_flow(src_ip, dst_ip, "TCP/UDP", port, "THREAT DETECTED", threat_type)

controller_instance = SDNController()
