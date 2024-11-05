## NS-3 Simulator and Gym:

![alt text](https://github.com/mrh996/AICD_Ns3ai/blob/main/contrib/ai/examples/DDoS_v2/use-gym/DDoS_v2%20scenario.png)

Network nodes:
 *  Switch (n0) is the victim switch managing the Victim LAN composed of servers and workstations
 *  Firewall (n1) is the victim router/firewall
 *  S1-S2 (n2-n3) are victim servers
 *  W1-W8 (n4-n11) are victim workstations
 *  Internet Router (n12) is the Internet entry point (e.g. ISP)
 *  B0-Bn (n13-n22) are bots DDoS-ing the victim network, where n=10
 *  C0-Cm (n23-n24) are legitimate users, communicating with servers S1 and S2 (data servers), where m=4

Simulation (start after X simulation seconds, stop after X simulation seconds) - note that MAX_SIMULATION_TIME = 10.0 (s):
 *  C0 establishes a TCP connection with S1 (0.1 s, MAX_SIMULATION_TIME - 5 s)
 *  C1 establishes a TCP connection with S1 (1.0 s, MAX_SIMULATION_TIME - 5 s)
 *  W1 establishes a TCP connection with S1 (2.0 s, 5.0 s)
 *  W2 establishes a TCP connection with S1 (3.0 s, 6.0 s)
 *  C2 establishes a TCP connection with S2 (0.1 s, MAX_SIMULATION_TIME - 5 s)
 *  C3 establishes a TCP connection with S2 (1.0 s, MAX_SIMULATION_TIME - 5 s)
 *  W3 establishes a TCP connection with S2 (2.0 s, 5.0 s)
 *  W4 establishes a TCP connection with S2 (3.0 s, 6.0 s)
 *  B0-B10 establish UDP connections with S1 (when required, MAX_SIMULATION_TIME - 1 s)

$ python run_ddosim.py

##	Exchanged stats:
    node_id                     # 1 - Node ID (a number if the stats are from a node, -1 if overall info of a flow)
    flow_id                     # 2 - Flow ID
    sim_time                    # 3 - Simulation time (elapsed seconds)
    src_addr                    # 4 - Source IPv4 address
    dst_addr                    # 5 - Destination IPv4 address
    src_port                    # 6 - Source port
    dst_ort                     # 7 - Destination port
    proto                       # 8 - Protocol
    time_first_tx_packet        # 9 - Time of the first TX packet (s)
    time_last_tx_packet         # 10 - Time of the last TX packet (s)
    time_first_rx_packet        # 11 - Time of the first RX packet (s)
    time_last_rx_packet         # 12 - Time of the last RX packet (s)
    tx_bytes                    # 13 - Sent bytes
    rx_bytes                    # 14 - Received bytes
    tx_pkts                     # 15 - Sent packets
    rx_pkts                     # 16 - Received packets
    forwarded_packets           # 17 - Number of forwarded packets
    dropped_packets             # 18 - Number of forwarded packets
    delay_sum                   # 19 - Total delay (s)
    jitter_sum                  # 20 - Total jitter (s)
    last_delay                  # 21 - Last delay value (s)
    throughput                  # 22 - Throughput (Mbps)
    flow_duration               # 23 - Flow duration (Last Tx - First Rx)
    pdr                         # 24 - Packet Delivery Ratio
    plr                         # 25 - Packet Loss Ratio
    average_tx_packet_size      # 26 - Average transmitted packet size (B)
    average_rx_packet_size      # 27 - Average received packet size (B)


Please note that the above flow stats (features) are collected per node (node_id >= 0) or per flow (node_id == -1) and are sent by ns3 to the OpenGym environment every time a node has an update. Note that if a node does not send packets, then it will not send any updates (e.g. W5 will not send any stats); this will avoid overloading the network with unnecessary empty stats.


In the OpenGym environment, the flow stats per node received are stored in the victim_nodes_logs dictionary and can be used to create a graph of the network. Meanwhile, the overall flow stats received are stored in the victim_flow_stats dictionary and can be used to provide a more high-level overview of the victim network status. 


It is important to note that a flow has a unique ID (starting from 1), and it is formed using the following information:
 - Source IPv4 address
 - Destination IPv4 address
 - Source port of the transport protocol (TCP or UDP)
 - Destination port of the transport protocol (TCP or UDP)
 - Transport protocol number (TCP==6 or UDP==17)


It is also important to note that packets generated in a flow pass through two (source and destination nodes) or more nodes (intermediate nodes). For example, stats about flow with ID 1 will be updated by C0 (source node), Internet Router, Victim Router/FW and Victim SW (intermediate nodes), and S1 (destination node).


Examples:
 - Flow ID 1 (10.0.1.2 - 10.1.2.2 - 49152 - 9000 - 6)
 - Flow ID 2 (10.0.3.2 - 10.1.2.3 - 49153 - 9000 - 6)
