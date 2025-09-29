 # simple_firewall.py

# --- 1. Configuration: The Firewall Ruleset ---

# Rules are checked in order. The first match determines the action.
# 'action': 'ALLOW' or 'DROP'
# 'protocol': 'TCP', 'UDP', or 'ANY'
# 'src_ip': A specific IP ('10.10.1.5') or 'ANY'
# 'dst_port': A specific port (e.g., 80, 22) or 'ANY'

FIREWALL_RULES = [
    {
        'action': 'ALLOW',
        'protocol': 'TCP',
        'src_ip': 'ANY',
        'dst_port': 80  # Allow all incoming web (HTTP) traffic
    },
    {
        'action': 'ALLOW',
        'protocol': 'TCP',
        'src_ip': '192.168.1.100', # Allow a specific administrative machine
        'dst_port': 22  # to use SSH
    },
    {
        'action': 'DROP',
        'protocol': 'UDP',
        'src_ip': 'ANY',
        'dst_port': 137 # Explicitly block NetBIOS (often a security risk)
    },
    # The final rule in a real firewall is often an implicit "Default Drop"
]

DEFAULT_POLICY = 'DROP' # If no rule matches, the packet is dropped

# --- 2. The Core Firewall Engine ---

def inspect_packet(packet, ruleset):
    """
    Simulates a firewall's packet inspection.
    Iterates through the rules and returns the action of the first matching rule.
    """
    print(f"\n--- Inspecting Packet from {packet['src_ip']} to Port {packet['dst_port']} ({packet['protocol']}) ---")
    
    # Iterate through the rules in the order they are defined
    for i, rule in enumerate(ruleset):
        
        # --- Rule Matching Logic ---
        
        # 1. Match Protocol
        protocol_match = (rule['protocol'] == 'ANY' or rule['protocol'] == packet['protocol'])
        
        # 2. Match Source IP
        ip_match = (rule['src_ip'] == 'ANY' or rule['src_ip'] == packet['src_ip'])
        
        # 3. Match Destination Port
        port_match = (rule['dst_port'] == 'ANY' or rule['dst_port'] == packet['dst_port'])

        # If ALL criteria are met, this rule is a match!
        if protocol_match and ip_match and port_match:
            print(f"RULE MATCHED (Rule #{i + 1}): {rule['action']} - {rule}")
            return rule['action'] # The "First Match Wins" principle
            
    # --- 3. Default Policy ---
    
    # If the loop finishes without returning, no rule matched.
    print(f"NO RULE MATCHED. Applying Default Policy: {DEFAULT_POLICY}")
    return DEFAULT_POLICY

# --- 4. Main Execution and Testing ---

if __name__ == "__main__":
    
    # Example 1: HTTP Traffic (Should be ALLOWED by Rule #1)
    packet_1 = {
        'protocol': 'TCP', 
        'src_ip': '10.50.5.20', 
        'dst_ip': '172.16.0.1', 
        'dst_port': 80
    }
    result_1 = inspect_packet(packet_1, FIREWALL_RULES)
    print(f"Final Action: **{result_1}**\n")

    # Example 2: SSH from the Admin machine (Should be ALLOWED by Rule #2)
    packet_2 = {
        'protocol': 'TCP', 
        'src_ip': '192.168.1.100', 
        'dst_ip': '172.16.0.1', 
        'dst_port': 22
    }
    result_2 = inspect_packet(packet_2, FIREWALL_RULES)
    print(f"Final Action: **{result_2}**\n")
    
    # Example 3: Random traffic (Should be DROPPED by Default Policy)
    packet_3 = {
        'protocol': 'TCP', 
        'src_ip': '10.50.5.20', 
        'dst_ip': '172.16.0.1', 
        'dst_port': 5000 
    }
    result_3 = inspect_packet(packet_3, FIREWALL_RULES)
    print(f"Final Action: **{result_3}**\n")

    # Example 4: Blocked UDP traffic (Should be DROPPED by Rule #3, before Default)
    packet_4 = {
        'protocol': 'UDP', 
        'src_ip': '10.50.5.20', 
        'dst_ip': '172.16.0.1', 
        'dst_port': 137 
    }
    result_4 = inspect_packet(packet_4, FIREWALL_RULES)
    print(f"Final Action: **{result_4}**")
