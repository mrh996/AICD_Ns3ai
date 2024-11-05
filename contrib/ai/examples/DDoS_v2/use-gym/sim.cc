/*
 * LICENSE : GNU General Public License v3.0 (https://github.com/Saket-Upadhyay/ns3-cybersecurity-simulations/blob/master/LICENSE)
 * REPOSITORY : https://github.com/Saket-Upadhyay/ns3-cybersecurity-simulations
 * =================================================================================
 *
 * In this we follow the following setup / node placement
 *
 *
 *     Victim Network                  Internet            Legitimate nodes
 *
 *         (SW) ---- (FW) ------------ (Router) ---------- (C0)...(Cm)
 *         (n0)      (n1)               (n12)              (n23)..(n26)
 *      _____|_______                   / |  \
 *     /    / \      \                 /  |   \
 *    /    /   \      \               /   |    \
 *  (S1),(S2),(W1)...(W8)           (B0),(B2)...(Bn)
 *  (n2),(n3),(n4)...(n11)         (n13),(n14)..(n22)
 *
 *                              Attacker Network (Botnet)
 *
 *  S1-S2 are victim servers
 *  W1-W8 are victim workstations
 *  SW is the victim switch managing the Victim LAN composed of servers and workstations
 *  FW is the victim router/firewall
 *  Router is the Internet entry point
 *  C0-Cm are legitimate users, communicating with servers S1 and S2 (data servers), where m=4
 *  B0-Bn are bots DDoS-ing the network, where n=10
 *
 * NetAnim XML is saved as -> DDoSim_v2.xml
 *
 * Modify: Valerio Selis <v.selis@liverpool.ac.uk>
 * Modify: Ronghui Mu <ronghui.mu@liverpool.ac.uk>
 *
 */
#include <ns3/csma-helper.h>
#include <ns3/ai-module.h>
#include "ns3/mobility-module.h"
#include "ns3/nstime.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/netanim-module.h"

#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"

#include "ns3/packet-metadata.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/trace-helper.h"

#include "ns3gymenv.h"

#include <iostream>
#include <unordered_map>
#include <string>

#define TCP_SINK_PORT 9000
#define UDP_SINK_PORT 9001

//Experimental parameters
#define MAX_BULK_BYTES 100000
#define DDOS_RATE "20480kb/s"
#define MAX_SIMULATION_TIME 10.0

//Number of bots for DDoS
#define NUMBER_OF_BOTS 10
//Number of legitimate clients
#define NUMBER_OF_CLIENTS 4

using namespace ns3;

// Used to retrieve flows and their stats
Ptr<FlowMonitor> monitor;
Ptr<Ipv4FlowClassifier> classifier;

// Map node IDs with features (flows' stats per node)
FeaturesMap nodeIdFeaturesMap;
// Map flow IDs with features (overall flows' stats)
FeaturesMap flowIdFeaturesMap;
// Store RX packet UIDs for each node to check forwarded packets
ForwardedMap nodeIdRxPacketsUids;
// ns3 - gym environment
Ptr<Ns3GymEnv> nge;

// Nodes within the victim LAN
NodeContainer csmaNodesVictim;
// Nodes for attack bots
NodeContainer botNodes;

// Used to determine if an attack has been performed
bool lastAction;

NS_LOG_COMPONENT_DEFINE("DDoSAttack");

void ApplyAction(uint32_t action, uint32_t targetNodeId) {
    switch (action) {
        case 0: // No attack or stop attack
            // Logic to stop the attack if necessary
            std::cout<< " No attack performed;";
            NS_LOG_UNCOND("No attack performed: " << action);
            return;
        case 1: // Perform DDoS attack
        {
            // Ensure that the attack starts after 1 second, starts now+1sec and can be executed (simulation time-1sec)
            if (Simulator::Now().GetSeconds() > 1.0 && Simulator::Now().GetSeconds() < MAX_SIMULATION_TIME - 1)
            {
                NS_LOG_UNCOND("Performing DDoS attack: " << action);
                lastAction = true;
                Ptr<Node> targetNode = csmaNodesVictim.Get(targetNodeId);
                Address targetAddress = Address(InetSocketAddress(targetNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal(), UDP_SINK_PORT));
                /*std::cout << " Attack node " << targetNode->GetId() 
                    << "  with address  " << targetNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal() 
                    << " at " <<Simulator::Now().GetSeconds() <<" s;"<< std::endl;*/
                OnOffHelper onoff("ns3::UdpSocketFactory", targetAddress);
                onoff.SetConstantRate(DataRate(DDOS_RATE));
                onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
                onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

                ApplicationContainer onOffApp[NUMBER_OF_BOTS];
                for (int k = 0; k < NUMBER_OF_BOTS; ++k) {
                    onOffApp[k] = onoff.Install(botNodes.Get(k));
                    onOffApp[k].Start(Seconds(Simulator::Now().GetSeconds()+1));
                    onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
                }
                std::cout << "Action performed" << std::endl;
                return;
            }
        }
        default:
            std::cout<< " Invalid action";
            NS_LOG_UNCOND("Invalid action received: " << action);
            return;
    }
}


/*
Convert an IPv4 address into unsigned int
*/
uint32_t Ipv4AddressToInt(ns3::Ipv4Address address)
{
    uint32_t addr = address.Get();
    uint32_t byte1 = (addr >> 24) & 0xFF;
    uint32_t byte2 = (addr >> 16) & 0xFF;
    uint32_t byte3 = (addr >> 8) & 0xFF;
    uint32_t byte4 = addr & 0xFF;

    return (byte1 * 256 * 256 * 256) + (byte2 * 256 * 256) + (byte3 * 256) + byte4;
}


/*
Monitor the flows and exchange info with the Gym env
*/
void Monitor () {
    monitor->CheckForLostPackets();

    // Victim Server 1
    Ptr<Node> node_server1 = csmaNodesVictim.Get(1);
    Ptr<Ipv4> ipv4_obj_server1 = node_server1->GetObject<Ipv4>();
    Ipv4Address ipv4_address_server1 = ipv4_obj_server1->GetAddress(1, 0).GetLocal();

    // Obtain stats about the flows
    std::map<FlowId, FlowMonitor::FlowStats> flowStats = monitor->GetFlowStats();
    
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator fs = flowStats.begin(); fs != flowStats.end(); ++fs) {
        Ipv4FlowClassifier::FiveTuple ft = classifier->FindFlow(fs->first);
        // Retrieve flow stats for the sink node (Server 1)
        if (ft.destinationAddress == Ipv4Address(ipv4_address_server1)) {
            // Info for the current flow
            // Stats for this flow
            FlowId flowId = fs->first;
            double currentSimTime = Simulator::Now().GetSeconds();
            // Check if there are already stats for this flow, if not, initialise the map object
            if (flowIdFeaturesMap.find(flowId) != flowIdFeaturesMap.end()) {
                flowIdFeaturesMap[flowId].simTime[0] = currentSimTime;
                flowIdFeaturesMap[flowId].timeFirstTxPacket[0] = fs->second.timeFirstTxPacket.GetSeconds();
                flowIdFeaturesMap[flowId].timeLastTxPacket[0] = fs->second.timeLastTxPacket.GetSeconds();
                flowIdFeaturesMap[flowId].timeFirstRxPacket[0] = fs->second.timeFirstRxPacket.GetSeconds();
                flowIdFeaturesMap[flowId].timeLastRxPacket[0] = fs->second.timeLastRxPacket.GetSeconds();
                flowIdFeaturesMap[flowId].txBytes[0] += fs->second.txBytes;
                flowIdFeaturesMap[flowId].rxBytes[0] += fs->second.rxBytes;
                flowIdFeaturesMap[flowId].txPackets[0] += fs->second.txPackets;
                flowIdFeaturesMap[flowId].rxPackets[0] += fs->second.rxPackets;
                flowIdFeaturesMap[flowId].forwardedPackets[0] = flowIdFeaturesMap[flowId].rxPackets[0];
                flowIdFeaturesMap[flowId].droppedPackets[0] += fs->second.lostPackets;
                flowIdFeaturesMap[flowId].delaySum[0] += fs->second.delaySum.GetSeconds();
                flowIdFeaturesMap[flowId].jitterSum[0] += fs->second.jitterSum.GetSeconds();
                flowIdFeaturesMap[flowId].lastDelay[0] = fs->second.lastDelay.GetSeconds();
            }
            else {
                flowIdFeaturesMap[flowId].flowId.push_back(flowId);
                flowIdFeaturesMap[flowId].srcAddr.push_back(Ipv4AddressToInt(ft.sourceAddress));
                flowIdFeaturesMap[flowId].dstAddr.push_back(Ipv4AddressToInt(ft.destinationAddress));
                flowIdFeaturesMap[flowId].srcPort.push_back(ft.sourcePort);
                flowIdFeaturesMap[flowId].dstPort.push_back(ft.destinationPort);
                flowIdFeaturesMap[flowId].proto.push_back(ft.protocol);
                flowIdFeaturesMap[flowId].simTime.push_back(currentSimTime);
                flowIdFeaturesMap[flowId].timeFirstTxPacket.push_back(fs->second.timeFirstTxPacket.GetSeconds());
                flowIdFeaturesMap[flowId].timeLastTxPacket.push_back(fs->second.timeLastTxPacket.GetSeconds());
                flowIdFeaturesMap[flowId].timeFirstRxPacket.push_back(fs->second.timeFirstRxPacket.GetSeconds());
                flowIdFeaturesMap[flowId].timeLastRxPacket.push_back(fs->second.timeLastRxPacket.GetSeconds());
                flowIdFeaturesMap[flowId].txBytes.push_back(fs->second.txBytes);
                flowIdFeaturesMap[flowId].rxBytes.push_back(fs->second.rxBytes);
                flowIdFeaturesMap[flowId].txPackets.push_back(fs->second.txPackets);
                flowIdFeaturesMap[flowId].rxPackets.push_back(fs->second.rxPackets);
                flowIdFeaturesMap[flowId].forwardedPackets.push_back(flowIdFeaturesMap[flowId].rxPackets[0]);
                flowIdFeaturesMap[flowId].droppedPackets.push_back(fs->second.lostPackets);
                flowIdFeaturesMap[flowId].delaySum.push_back(fs->second.delaySum.GetSeconds());
                flowIdFeaturesMap[flowId].jitterSum.push_back(fs->second.jitterSum.GetSeconds());
                flowIdFeaturesMap[flowId].lastDelay.push_back(fs->second.lastDelay.GetSeconds());
            }
            
            // Set the stats to be sent to the Gym env
            nge->SetStats(-1, flowId, -1, flowIdFeaturesMap);

            // Notify for new flow stats and get action(s) from Gym env
            uint32_t action = nge->NotifyGetAction();
            //std::cout << "Monitor - get_action: " << action << ";" << std::endl;
            //std::cout << "Monitor - Simulation time: " << currentSimTime << " s;" << std::endl;
            
            // Avoid to perform another attack if this has been already launched
            if(lastAction == false)
                ApplyAction(action, 1);
            //Simulator::Schedule(Seconds(0.0), &ApplyAction, action, 1);
        }
    }
    // Schedule after one second
    Simulator::Schedule(Seconds(1), &Monitor);
}

void extract_features(Ptr<const Packet> packet, uint32_t nodeID, const std::string &eventType) {
    //packet->Print(std::cout);
    // Create a copy of the packet to parse it
    Ptr<Packet> packetCopy = packet->Copy();

    uint32_t packetBytes = packetCopy->GetSize();                       // Packet bytes
    //std::cout << "Extract feature  " << eventType  << std::endl;
    double currentSimTime = Simulator::Now().GetSeconds();

    int forwarded = 0;
    // If a packet is received save its Uid for the current node
    if (eventType == "Rx") {
        nodeIdRxPacketsUids[nodeID].push_back(packetCopy->GetUid());
    }
    else {
        // If a packet is transmitted check if it was received by the same node and remove the Uid
        if (eventType == "Tx") {
            // Retrieve the index of the packet Uid
            auto it = std::find(nodeIdRxPacketsUids[nodeID].begin(), nodeIdRxPacketsUids[nodeID].end(), packetCopy->GetUid()); 
  
            // If the packet Uid is found, the packet has been forwarded, then remove the Uid
            if (it != nodeIdRxPacketsUids[nodeID].end()) { 
                forwarded = 1;
                nodeIdRxPacketsUids[nodeID].erase(it); 
            } 
        }
    }

    // Extract info from the IPv4 header
    Ipv4Header ipv4Header;
    packetCopy->RemoveHeader(ipv4Header);

    uint32_t srcAddr = Ipv4AddressToInt(ipv4Header.GetSource());        // Source address
    uint32_t dstAddr = Ipv4AddressToInt(ipv4Header.GetDestination());   // Destination address
    uint8_t proto = ipv4Header.GetProtocol();                           // Protocol

    uint16_t srcPort = 0;                                               // Source port
    uint16_t dstPort = 0;                                               // Destination port

    Ipv4FlowClassifier::FiveTuple t;
    t.sourceAddress = ipv4Header.GetSource();
    t.destinationAddress = ipv4Header.GetDestination();
    t.protocol = proto;

    // Extract info from the UDP header
    if(proto == UdpL4Protocol::PROT_NUMBER) {
        //std::cout << "UDP!!! " << std::endl;
        UdpHeader udpHeader;
        packetCopy->RemoveHeader(udpHeader);
        srcPort = udpHeader.GetSourcePort();
        dstPort = udpHeader.GetDestinationPort();
        t.sourcePort = udpHeader.GetSourcePort();
        t.destinationPort = udpHeader.GetDestinationPort();
    }
    // Extract info from the TCP header
    else if(proto == TcpL4Protocol::PROT_NUMBER) {
        //std::cout << "TCP!!! " << std::endl;
        TcpHeader tcpHeader;
        packetCopy->RemoveHeader(tcpHeader);
        srcPort = tcpHeader.GetSourcePort();
        dstPort = tcpHeader.GetDestinationPort();
        t.sourcePort = tcpHeader.GetSourcePort();
        t.destinationPort = tcpHeader.GetDestinationPort();
    } else {
        std::cout << "This should never happen!" << std::endl;
        return;
    }

    //std::cout << "Map flowID  "  << std::endl;
    uint32_t flowId = 0;
    // Iterate through the recorded flows to find a match
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    //for (const auto& flow : stats) {
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator fs = stats.begin(); fs != stats.end(); ++fs) {
        Ipv4FlowClassifier::FiveTuple flowTuple = classifier->FindFlow(fs->first);
        if (flowTuple == t) {
            flowId = fs->first; // Found the matching FlowId
            break;
        }
    }

    // Save the index for the current flow
    uint32_t flowIndex = 0;
    //std::cout << "Create dict for nodeid " << nodeID << "   flowid " << flowId << std::endl;
    // Check if the nodeId is already in the dictionary
    if (nodeIdFeaturesMap.find(nodeID) != nodeIdFeaturesMap.end()) {
        // Node Id is in the dictionary so update stats
        auto it = find(nodeIdFeaturesMap[nodeID].flowId.begin(), nodeIdFeaturesMap[nodeID].flowId.end(), flowId);
        // Checking if Flow Id is found or not
        if (it != nodeIdFeaturesMap[nodeID].flowId.end()) {
            // Flow Id already present for an existing node, update stats
            uint32_t index = it - nodeIdFeaturesMap[nodeID].flowId.begin();
            flowIndex = index;
            //std::cout << "Existing flow id for existing node at index: " << nodeID << " - " << flowId << " - " << index + 1 << std::endl;
            nodeIdFeaturesMap[nodeID].simTime[index] = currentSimTime;
            if (eventType == "Tx") {
                nodeIdFeaturesMap[nodeID].timeLastTxPacket[index] = currentSimTime;
                nodeIdFeaturesMap[nodeID].txBytes[index] += packetBytes;
                nodeIdFeaturesMap[nodeID].txPackets[index] += 1;
                if (forwarded == 1)
                    nodeIdFeaturesMap[nodeID].forwardedPackets[index] += 1;
            } else if (eventType == "Rx") {
                nodeIdFeaturesMap[nodeID].timeLastRxPacket[index] = currentSimTime;
                nodeIdFeaturesMap[nodeID].rxBytes[index] += packetBytes;
                nodeIdFeaturesMap[nodeID].rxPackets[index] += 1;
                if (nodeIdFeaturesMap[nodeID].txPackets[index] > 0) { // This assumes no computational delays within an end node
                    double delay = currentSimTime - nodeIdFeaturesMap[nodeID].timeLastTxPacket[index];
                    nodeIdFeaturesMap[nodeID].delaySum[index] += delay;
                    if (nodeIdFeaturesMap[nodeID].lastDelay[index] > 0) {
                        nodeIdFeaturesMap[nodeID].jitterSum[index] += fabs(delay - nodeIdFeaturesMap[nodeID].lastDelay[index]);
                    }
                    nodeIdFeaturesMap[nodeID].lastDelay[index] = delay;
                }
            } else if (eventType == "Drop") {
                nodeIdFeaturesMap[nodeID].droppedPackets[index] += 1;
            }
        } else {
            // New Flow Id for an existing node, init stats
            //std::cout << "New flow id for existing node: " << nodeID << " - " << flowId << std::endl;
            // Here we take the vector size() because then we insert a new item
            flowIndex = nodeIdFeaturesMap[nodeID].flowId.size();
            nodeIdFeaturesMap[nodeID].flowId.push_back(flowId);
            nodeIdFeaturesMap[nodeID].simTime.push_back(currentSimTime);
            nodeIdFeaturesMap[nodeID].srcAddr.push_back(srcAddr);
            nodeIdFeaturesMap[nodeID].dstAddr.push_back(dstAddr);
            nodeIdFeaturesMap[nodeID].srcPort.push_back(srcPort);
            nodeIdFeaturesMap[nodeID].dstPort.push_back(dstPort);
            nodeIdFeaturesMap[nodeID].proto.push_back(proto);
            if (eventType == "Tx") {
                nodeIdFeaturesMap[nodeID].timeFirstTxPacket.push_back(currentSimTime);
                nodeIdFeaturesMap[nodeID].timeLastTxPacket.push_back(currentSimTime);
                nodeIdFeaturesMap[nodeID].timeFirstRxPacket.push_back(0.0);
                nodeIdFeaturesMap[nodeID].timeLastRxPacket.push_back(0.0);
                nodeIdFeaturesMap[nodeID].txBytes.push_back(packetBytes);
                nodeIdFeaturesMap[nodeID].rxBytes.push_back(0.0);
                nodeIdFeaturesMap[nodeID].txPackets.push_back(1.0);
                nodeIdFeaturesMap[nodeID].rxPackets.push_back(0.0);
                if (forwarded == 1)
                    nodeIdFeaturesMap[nodeID].forwardedPackets.push_back(1.0);
                else
                    nodeIdFeaturesMap[nodeID].forwardedPackets.push_back(0.0);
                nodeIdFeaturesMap[nodeID].droppedPackets.push_back(0.0);
                nodeIdFeaturesMap[nodeID].delaySum.push_back(0.0);
                nodeIdFeaturesMap[nodeID].jitterSum.push_back(0.0);
                nodeIdFeaturesMap[nodeID].lastDelay.push_back(0.0);
            } else if (eventType == "Rx") {
                nodeIdFeaturesMap[nodeID].timeFirstTxPacket.push_back(0.0);
                nodeIdFeaturesMap[nodeID].timeLastTxPacket.push_back(0.0);
                nodeIdFeaturesMap[nodeID].timeFirstRxPacket.push_back(currentSimTime);
                nodeIdFeaturesMap[nodeID].timeLastRxPacket.push_back(currentSimTime);
                nodeIdFeaturesMap[nodeID].txBytes.push_back(0.0);
                nodeIdFeaturesMap[nodeID].rxBytes.push_back(packetBytes);
                nodeIdFeaturesMap[nodeID].txPackets.push_back(0.0);
                nodeIdFeaturesMap[nodeID].rxPackets.push_back(1.0);
                nodeIdFeaturesMap[nodeID].forwardedPackets.push_back(0.0);
                nodeIdFeaturesMap[nodeID].droppedPackets.push_back(0.0);
                nodeIdFeaturesMap[nodeID].delaySum.push_back(0.0);
                nodeIdFeaturesMap[nodeID].jitterSum.push_back(0.0);
                nodeIdFeaturesMap[nodeID].lastDelay.push_back(0.0);
            } else if (eventType == "Drop") {
                nodeIdFeaturesMap[nodeID].timeFirstTxPacket.push_back(0.0);
                nodeIdFeaturesMap[nodeID].timeLastTxPacket.push_back(0.0);
                nodeIdFeaturesMap[nodeID].timeFirstRxPacket.push_back(0.0);
                nodeIdFeaturesMap[nodeID].timeLastRxPacket.push_back(0.0);
                nodeIdFeaturesMap[nodeID].txBytes.push_back(0.0);
                nodeIdFeaturesMap[nodeID].rxBytes.push_back(0.0);
                nodeIdFeaturesMap[nodeID].txPackets.push_back(0.0);
                nodeIdFeaturesMap[nodeID].rxPackets.push_back(0.0);
                nodeIdFeaturesMap[nodeID].forwardedPackets.push_back(0.0);
                nodeIdFeaturesMap[nodeID].droppedPackets.push_back(1.0);
                nodeIdFeaturesMap[nodeID].delaySum.push_back(0.0);
                nodeIdFeaturesMap[nodeID].jitterSum.push_back(0.0);
                nodeIdFeaturesMap[nodeID].lastDelay.push_back(0.0);
            }
        }
    }
	else {
        // Node Id is not in the dictionary so init stats
        //std::cout << "Node id not in the dictionary; add: " << nodeID << std::endl;
        nodeIdFeaturesMap[nodeID].flowId.push_back(flowId);
        nodeIdFeaturesMap[nodeID].simTime.push_back(currentSimTime);
        nodeIdFeaturesMap[nodeID].srcAddr.push_back(srcAddr);
        nodeIdFeaturesMap[nodeID].dstAddr.push_back(dstAddr);
        nodeIdFeaturesMap[nodeID].srcPort.push_back(srcPort);
        nodeIdFeaturesMap[nodeID].dstPort.push_back(dstPort);
        nodeIdFeaturesMap[nodeID].proto.push_back(proto);
        if (eventType == "Tx") {
            nodeIdFeaturesMap[nodeID].timeFirstTxPacket.push_back(currentSimTime);
            nodeIdFeaturesMap[nodeID].timeLastTxPacket.push_back(currentSimTime);
            nodeIdFeaturesMap[nodeID].timeFirstRxPacket.push_back(0.0);
            nodeIdFeaturesMap[nodeID].timeLastRxPacket.push_back(0.0);
            nodeIdFeaturesMap[nodeID].txBytes.push_back(packetBytes);
            nodeIdFeaturesMap[nodeID].rxBytes.push_back(0.0);
            nodeIdFeaturesMap[nodeID].txPackets.push_back(1.0);
            nodeIdFeaturesMap[nodeID].rxPackets.push_back(0.0);
            if (forwarded == 1)
                nodeIdFeaturesMap[nodeID].forwardedPackets.push_back(1.0);
            else
                nodeIdFeaturesMap[nodeID].forwardedPackets.push_back(0.0);
            nodeIdFeaturesMap[nodeID].droppedPackets.push_back(0.0);
            nodeIdFeaturesMap[nodeID].delaySum.push_back(0.0);
            nodeIdFeaturesMap[nodeID].jitterSum.push_back(0.0);
            nodeIdFeaturesMap[nodeID].lastDelay.push_back(0.0);
        } else if (eventType == "Rx") {
            nodeIdFeaturesMap[nodeID].timeFirstTxPacket.push_back(0.0);
            nodeIdFeaturesMap[nodeID].timeLastTxPacket.push_back(0.0);
            nodeIdFeaturesMap[nodeID].timeFirstRxPacket.push_back(currentSimTime);
            nodeIdFeaturesMap[nodeID].timeLastRxPacket.push_back(currentSimTime);
            nodeIdFeaturesMap[nodeID].txBytes.push_back(0.0);
            nodeIdFeaturesMap[nodeID].rxBytes.push_back(packetBytes);
            nodeIdFeaturesMap[nodeID].txPackets.push_back(0.0);
            nodeIdFeaturesMap[nodeID].rxPackets.push_back(1.0);
            nodeIdFeaturesMap[nodeID].forwardedPackets.push_back(0.0);
            nodeIdFeaturesMap[nodeID].droppedPackets.push_back(0.0);
            nodeIdFeaturesMap[nodeID].delaySum.push_back(0.0);
            nodeIdFeaturesMap[nodeID].jitterSum.push_back(0.0);
            nodeIdFeaturesMap[nodeID].lastDelay.push_back(0.0);
        } else if (eventType == "Drop") {
            nodeIdFeaturesMap[nodeID].timeFirstTxPacket.push_back(0.0);
            nodeIdFeaturesMap[nodeID].timeLastTxPacket.push_back(0.0);
            nodeIdFeaturesMap[nodeID].timeFirstRxPacket.push_back(0.0);
            nodeIdFeaturesMap[nodeID].timeLastRxPacket.push_back(0.0);
            nodeIdFeaturesMap[nodeID].txBytes.push_back(0.0);
            nodeIdFeaturesMap[nodeID].rxBytes.push_back(0.0);
            nodeIdFeaturesMap[nodeID].txPackets.push_back(0.0);
            nodeIdFeaturesMap[nodeID].rxPackets.push_back(0.0);
            nodeIdFeaturesMap[nodeID].forwardedPackets.push_back(0.0);
            nodeIdFeaturesMap[nodeID].droppedPackets.push_back(1.0);
            nodeIdFeaturesMap[nodeID].delaySum.push_back(0.0);
            nodeIdFeaturesMap[nodeID].jitterSum.push_back(0.0);
            nodeIdFeaturesMap[nodeID].lastDelay.push_back(0.0);
        }
    }
    
    /*
    std::cout << std::endl << "NodeID: " << nodeID << " - " << eventType << " - FlowId: " << nodeIdFeaturesMap[nodeID].flowId[flowIndex] 
                << " - Sim Time: " << nodeIdFeaturesMap[nodeID].simTime[flowIndex] 
                << " - Source IP: " << ipv4Header.GetSource() << " - " << nodeIdFeaturesMap[nodeID].srcAddr[flowIndex] 
                << " - Destination IP: " << ipv4Header.GetDestination() << " - " << nodeIdFeaturesMap[nodeID].dstAddr[flowIndex]
                << " - Source Port: " << nodeIdFeaturesMap[nodeID].srcPort[flowIndex] 
                << " - Destination Port: " << nodeIdFeaturesMap[nodeID].dstPort[flowIndex]
                << " - Protocol: " << static_cast<uint32_t>(nodeIdFeaturesMap[nodeID].proto[flowIndex])
                << " - Tx bytes: " << nodeIdFeaturesMap[nodeID].txBytes[flowIndex] 
                << " - Rx bytes: " << nodeIdFeaturesMap[nodeID].rxBytes[flowIndex] 
                << " - Tx Packets: " << nodeIdFeaturesMap[nodeID].txPackets[flowIndex] 
                << " - Rx Packets: " << nodeIdFeaturesMap[nodeID].rxPackets[flowIndex] 
                << " - Forwarded Packets: " << nodeIdFeaturesMap[nodeID].forwardedPackets[flowIndex] 
                << " - Dropped Packets: " << nodeIdFeaturesMap[nodeID].droppedPackets[flowIndex] 
                << " - Delay: " << nodeIdFeaturesMap[nodeID].delaySum[flowIndex] 
                << " - Jitter: " << nodeIdFeaturesMap[nodeID].jitterSum[flowIndex]  << std::endl;
    */
    
    // Set the stats to be sent to the Gym env
    //std::cout << "Send dict to Gym env for nodeid " << nodeID << "   flowid " << flowId << std::endl;
    std::cout << "Extract features - Simulation time: " << currentSimTime << " s;" << std::endl;
    nge->SetStats(nodeID, flowId, flowIndex, nodeIdFeaturesMap);

    // Notify for new flow stats and get action(s) from Gym env
    uint32_t action = nge->NotifyGetAction();
    std::cout << "Extract features - get_action: " << action << ";" << std::endl;
    
    // Avoid to perform another attack if this has been already launched
    if(lastAction == false)
        ApplyAction(action, 1);
}

/*
Callback to trace information about Tx packets and exchange info with the Gym env
*/
void TxPacketTraceCallback(Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface)
{
    //std::cout << std::endl << "***** Packet Tx *****  "<< std::endl;
    extract_features(packet, ipv4->GetObject<Node>()->GetId(), "Tx");
}

/*
Callback to trace information about Rx packets and exchange info with the Gym env
*/
void RxPacketTraceCallback(Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface)
{
    //std::cout << std::endl << "***** Packet Rx *****  "<< std::endl;
    extract_features(packet, ipv4->GetObject<Node>()->GetId(), "Rx");
}

int main (int argc, char *argv[])
{
    bool verbose = true;
    lastAction = false;
    // Number of Switches (SW) and Routers/Firewalls (FW)
    uint32_t nP2pVictim = 2;
    // Number of Servers and Workstations
    uint32_t nCsmaVictim = 10;

    CommandLine cmd;
    cmd.AddValue("nCsma", "Number of \"extra\" CSMA nodes/devices", nCsmaVictim);
    cmd.AddValue("verbose", "Tell echo applications to log if true", verbose);

    cmd.Parse(argc, argv);

    // Used to map store the NodeIDs of all victim nodes
    std::vector<Ptr<Node>> victimNodeIDs;

    Time::SetResolution(Time::NS);
    if (verbose) {
        LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
        LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
        Packet::EnablePrinting();
    }

    // OpenGym Env --- has to be created before any other thing
    Ptr<OpenGymInterface> openGymInterface = OpenGymInterface::Get();
    nge = CreateObject<Ns3GymEnv>();

    nCsmaVictim = nCsmaVictim == 0 ? 1 : nCsmaVictim;

    // SW Victim (0) and Router/FW Victim (1)
    NodeContainer p2pNodesVictim;
    p2pNodesVictim.Create(nP2pVictim);
    // Add the created node IDs into the list
    for (uint32_t i = 0; i < p2pNodesVictim.GetN(); ++i) {
        victimNodeIDs.push_back(p2pNodesVictim.Get(i));
    }
    
    // Victim LAN nodes (2 servers and 8 workstations connected to the SW Victim)
    csmaNodesVictim.Add(p2pNodesVictim.Get(0)); // SW Victim (0)
    csmaNodesVictim.Create(nCsmaVictim);        // Servers (1 and 2) and Workstations (3 to 11)
    // Add the created node IDs into the list (start from 1 as node 0 is the SW Victim)
    for (uint32_t i = 1; i < csmaNodesVictim.GetN(); ++i) {
        victimNodeIDs.push_back(csmaNodesVictim.Get(i));
    }

    // Internet Router for Attacker and Normal nodes
    NodeContainer p2pNodesInternet;
    p2pNodesInternet.Create(1);
    
    // Nodes for attack bots
    botNodes.Create(NUMBER_OF_BOTS);
    
    // Nodes for normal clients
    NodeContainer clientNodes;
    clientNodes.Create(4);
    
    // Victim Network (pp1), Internet (pp2), Attacker/Normal (pp3) links
    PointToPointHelper pp1, pp2, pp3;
    pp1.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pp1.SetChannelAttribute("Delay", StringValue("1ms"));
    
    pp2.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pp2.SetChannelAttribute("Delay", StringValue("1ms"));
    
    pp3.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pp3.SetChannelAttribute("Delay", StringValue("1ms"));

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));
    
    NetDeviceContainer p2pDevicesVictim;
    p2pDevicesVictim = pp1.Install(p2pNodesVictim);

    NetDeviceContainer p2pDevicesInternet;
    p2pDevicesInternet = pp2.Install(p2pNodesVictim.Get(1), p2pNodesInternet.Get(0));
    
    NetDeviceContainer botDeviceContainer[NUMBER_OF_BOTS];
    for (int i = 0; i < NUMBER_OF_BOTS; ++i) {
        botDeviceContainer[i] = pp3.Install(p2pNodesInternet.Get(0), botNodes.Get(i));
    }
    
    NetDeviceContainer clientDevicesContainer[NUMBER_OF_CLIENTS];
    for (int i = 0; i < NUMBER_OF_CLIENTS; ++i) {
        clientDevicesContainer[i] = pp3.Install(p2pNodesInternet.Get(0), clientNodes.Get(i));
    }

    NetDeviceContainer csmaDevicesVictim;
    csmaDevicesVictim = csma.Install(csmaNodesVictim);
    
    InternetStackHelper stack;
    stack.Install(p2pNodesVictim.Get(1));  // FW Victim
    stack.Install(csmaNodesVictim);        // Victim LAN nodes and Router Victim
    stack.Install(p2pNodesInternet);       // Internet Router Attacker/Normal (e.g. ISP)
    stack.Install(clientNodes);            // Legitimate clients
    stack.Install(botNodes);               // Bots

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer p2pInterfacesVictim = address.Assign(p2pDevicesVictim);
    
    // Enable IP forwarding on the Router/FW Victim
    Ptr<Ipv4> ipv4 = p2pNodesVictim.Get(1)->GetObject<Ipv4>();
    ipv4->SetAttribute("IpForward", BooleanValue(true));

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer csmaInterfacesVictim = address.Assign(csmaDevicesVictim);
    
    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer p2pInterfacesInternet = address.Assign(p2pDevicesInternet);

    address.SetBase("10.0.0.0", "255.255.255.252");
    for (int j = 0; j < NUMBER_OF_BOTS; ++j) {
        address.Assign(botDeviceContainer[j]);
        address.NewNetwork();
    }
    
    address.SetBase("10.0.1.0", "255.255.255.0");
    for (int j = 0; j < NUMBER_OF_CLIENTS; ++j) {
        address.Assign(clientDevicesContainer[j]);
        address.NewNetwork();
    }
    
    /*
    // DDoS Application Behaviour
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(csmaInterfacesVictim.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(DDOS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp[NUMBER_OF_BOTS];
    
    //Install application in all bots
    for (int k = 0; k < NUMBER_OF_BOTS; ++k) {
        onOffApp[k] = onoff.Install(botNodes.Get(k));
        onOffApp[k].Start(Seconds(0.0));
        onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
    }
    */
    
    // Legitimate client connection to Server 1 in the Victim LAN (node 1)
    // Sender Application (Packets generated by this application are throttled)
    BulkSendHelper bulkSendServer1("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(1), TCP_SINK_PORT));
    bulkSendServer1.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));
    ApplicationContainer bulkSendServer1App1 = bulkSendServer1.Install(clientNodes.Get(0)); // Legitimate client 1
    ApplicationContainer bulkSendServer1App2 = bulkSendServer1.Install(clientNodes.Get(1)); // Legitimate client 2
    ApplicationContainer bulkSendServer1App3 = bulkSendServer1.Install(csmaNodesVictim.Get(3)); // Victim workstation 1
    ApplicationContainer bulkSendServer1App4 = bulkSendServer1.Install(csmaNodesVictim.Get(4)); // Victim workstation 2
    bulkSendServer1App1.Start(Seconds(0.1));
    bulkSendServer1App1.Stop(Seconds(MAX_SIMULATION_TIME - 5));
    bulkSendServer1App2.Start(Seconds(1.0));
    bulkSendServer1App2.Stop(Seconds(MAX_SIMULATION_TIME - 5));
    bulkSendServer1App3.Start(Seconds(2.0));
    bulkSendServer1App3.Stop(Seconds(5.0));
    bulkSendServer1App4.Start(Seconds(3.0));
    bulkSendServer1App4.Stop(Seconds(6.0));

    // Legitimate client connections to Server 2 in the Victim LAN (node 2)
    // Sender Application (Packets generated by this application are throttled)
    BulkSendHelper bulkSendServer2("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(2), TCP_SINK_PORT));
    bulkSendServer2.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));
    ApplicationContainer bulkSendServer2App1 = bulkSendServer2.Install(clientNodes.Get(2)); // Legitimate client 3
    ApplicationContainer bulkSendServer2App2 = bulkSendServer2.Install(clientNodes.Get(3)); // Legitimate client 4
    ApplicationContainer bulkSendServer2App3 = bulkSendServer2.Install(csmaNodesVictim.Get(5)); // Victim workstation 3
    ApplicationContainer bulkSendServer2App4 = bulkSendServer2.Install(csmaNodesVictim.Get(6)); // Victim workstation 4
    bulkSendServer2App1.Start(Seconds(0.1));
    bulkSendServer2App1.Stop(Seconds(MAX_SIMULATION_TIME - 5));
    bulkSendServer2App2.Start(Seconds(1.0));
    bulkSendServer2App2.Stop(Seconds(MAX_SIMULATION_TIME - 5));
    bulkSendServer2App3.Start(Seconds(2.0));
    bulkSendServer2App3.Stop(Seconds(5.0));
    bulkSendServer2App4.Start(Seconds(3.0));
    bulkSendServer2App4.Stop(Seconds(6.0));
    
    // UDP Sink on receiver side
    PacketSinkHelper UDPsink("ns3::UdpSocketFactory",
                             Address(InetSocketAddress(Ipv4Address::GetAny(), UDP_SINK_PORT)));
    ApplicationContainer UDPSinkApp = UDPsink.Install(csmaNodesVictim.Get(1));   // UDP Server (1)
    UDPSinkApp.Start(Seconds(0.0));
    UDPSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // TCP Sink Application on server side
    PacketSinkHelper TCPsink("ns3::TcpSocketFactory",
                             InetSocketAddress(Ipv4Address::GetAny(), TCP_SINK_PORT));
    ApplicationContainer TCPSinkApp = TCPsink.Install(csmaNodesVictim.Get(1));   // TCP Server (1)
    TCPSinkApp.Start(Seconds(0.0));
    TCPSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    
    MobilityHelper mobility;

    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0), "MinY", DoubleValue(0.0), "DeltaX", DoubleValue(5.0), "DeltaY", DoubleValue(10.0),
                                  "GridWidth", UintegerValue(5), "LayoutType", StringValue("RowFirst"));

    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    mobility.Install(p2pNodesVictim);
    mobility.Install(csmaNodesVictim);
    mobility.Install(p2pNodesInternet);
    mobility.Install(clientNodes);
    mobility.Install(botNodes);

    //pp1.EnablePcapAll("second");
    //csmaVictim.EnablePcap("second", csmaDevicesVictim.Get(1), true);
    csma.EnablePcapAll ("csma-one-subnet", false);

    // Set up NetAnim
    AnimationInterface anim ("DDoSim_v2.xml");
    anim.SetMaxPktsPerTraceFile(50000000);

    // Assign positions to nodes for better visualization in NetAnim
    anim.SetConstantPosition (p2pNodesVictim.Get(0), 10, 10);  // Victim SW
    anim.SetConstantPosition (p2pNodesVictim.Get(1), 20, 10);  // Victim Router/FW
  
    uint32_t x_pos = 5; // Victim LAN nodes except Victim SW (0)
    for (uint32_t l = 1; l < csmaNodesVictim.GetN(); ++l)
    {
        ns3::AnimationInterface::SetConstantPosition(csmaNodesVictim.Get(l), x_pos++, 16);
    }
    
    ns3::AnimationInterface::SetConstantPosition(p2pNodesInternet.Get(0), 40, 15);

    x_pos = 40;
    for (int l = 0; l < NUMBER_OF_CLIENTS; ++l)
    {
        ns3::AnimationInterface::SetConstantPosition(clientNodes.Get(l), x_pos++, 5);
    }

    x_pos = 40;
    for (int l = 0; l < NUMBER_OF_BOTS; ++l)
    {
        ns3::AnimationInterface::SetConstantPosition(botNodes.Get(l), x_pos++, 25);
    }
    
    // Monitor the flow(s) and export stats to XML
    FlowMonitorHelper flowmonHelper;
    monitor = flowmonHelper.InstallAll();
    monitor->SerializeToXmlFile("flowmonitor.xml", true, true);
    classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());

    // Attach the callback to trace packets passing through the nodes within the victim network
    for (uint32_t i = 0; i < p2pNodesVictim.GetN(); ++i)
    {
        Ptr<Ipv4> ipv4 = p2pNodesVictim.Get(i)->GetObject<Ipv4>();
        ipv4->TraceConnectWithoutContext("Tx", MakeCallback(&TxPacketTraceCallback));
        ipv4->TraceConnectWithoutContext("Rx", MakeCallback(&RxPacketTraceCallback));
    }
    for (uint32_t i = 1; i < csmaNodesVictim.GetN(); ++i)
    {
        Ptr<Ipv4> ipv4 = csmaNodesVictim.Get(i)->GetObject<Ipv4>();
        ipv4->TraceConnectWithoutContext("Tx", MakeCallback(&TxPacketTraceCallback));
        ipv4->TraceConnectWithoutContext("Rx", MakeCallback(&RxPacketTraceCallback));
    }

    // Monitor overall flow stats per second
    Monitor();

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}