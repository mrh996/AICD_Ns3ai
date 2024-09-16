## NS-3 Simulator and Gym:

$ python run_ddosim.py

##	Exchanged stats:
    node_id                     # 1 - Node ID (number if info of a node, -1 if overall info of a flow)
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


Please note that the above flow stats (features) are collected per node (node_id >= 0) or per flow (node_id == -1).


The flow stats per node can be used to create a graph of the network. It is important to note that a flow has a unique ID (starting from 1) and it is formed by using the following information:
 - Source IPv4 address
 - Destination IPv4 address
 - Source port of the transport protocol (TCP or UDP)
 - Destination port of the transport protocol (TCP or UDP)
 - Transport protocol number (TCP==6 or UDP==17)
 

For example:
Flow ID 1 (192.168.0.1 - 192.168.3.1 - 45500 - 80 - 6)
Flow ID 2 (192.168.3.1 - 192.168.0.1 - 80 - 45500 - 6)


