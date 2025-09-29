## Basic Firewall

## Objective
The project is aimed to develop a clear and observable mechanism for testing data against business rules to ensure the reliability of the security policy. This involved creating distinct test packets with predictable outcomes, the project aims to demonstrate the correctness and integrity of the firewall engine's logic under various network traffic conditions. 

### Skills Learned

- Advanced Programming and Logic
- Deep Networking Fundamentals
- Security Engineering and Policy Managment

### Tools Used
- Python 3
- Standard Python Library
  
## The Code
This code inspects incoming network packets (represented as Python dictionaries) and applying a set of rules to determine their fate (Allow or Drop).
```python
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
```

<img width="1068" height="425" alt="basicfirewall" src="https://github.com/user-attachments/assets/09a73ed7-c6fb-4361-a914-5ac896b04012" />

Ref 1: Firewall outcome


### Outcome Explanation

How the Code Works
- Ruleset Definition: The FIREWALL_RULES list defines the policy.
  
- Inspection Function: The inspect_packet function takes a simulated packet and the ruleset. It iterates through the rules, comparing the packet's protocol, source IP, and destination port to the rule's criteria.

- Matching: For a rule to match, all its specified fields must match the packet's fields.

- Resolution: As soon as a full match is found, the loop terminates, and the rule's action (ALLOW or DROP) is returned.

- Default Policy: If the function completes its loop without finding a match, the traffic is subject to the DEFAULT_POLICY, which is set to 'DROP', ensuring maximum security by blocking all unapproved traffic.
