# controller/routing.py

def calculate_route(src_ip, dst_ip, is_threat=False):
    """
    Simulates calculating a route through the SDN network.
    
    Topology:
    Customer -> S1 -> S2 -> Bank Server
                   -> S3 -> Payment Gateway
                   -> S4 -> Honeypot
    """
    
    original_route = "Customer → S1 → S2 → Bank Server"
    
    if is_threat:
        # If it's a threat, we might reroute it to the honeypot or isolate it
        new_route = "Customer → S1 → S4 (Honeypot/Isolated)"
        action = "REROUTED"
        status = "SECURE"
    else:
        new_route = original_route
        action = "ALLOW"
        status = "SAFE"
        
    return original_route, new_route, action, status
