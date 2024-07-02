/*
 * LICENSE : GNU General Public License v3.0 (https://github.com/Saket-Upadhyay/ns3-cybersecurity-simulations/blob/master/LICENSE)
 * REPOSITORY : https://github.com/Saket-Upadhyay/ns3-cybersecurity-simulations
 * =================================================================================
 *
 * In this we follow the following setup / node placement
 *
 *
 *     Victim Network       Internet                 Legitimate nodes
 *
 *         (SW) ---- (FW) ------------ (Router) ---------- (C0)
 *      _____|_______                   / |  \
 *     /    / \      \                 /  |   \
 *    /    /   \      \               /   |    \
 *  (S1),(S2),(W1)...(W8)           (B0),(B2)...(Bn)
 *
 *                              Attacker Network (Botnet)
 *
 *  S1-S2 are victim servers
 *  W1-W8 are victim workstations
 *  SW is the victim switch managing the Victim LAN composed of servers and workstations
 *  FW is the victim router/firewall
 *  Router is the Internet entry point
 *  C0 is legitimate user, communicating with server S1 (data server)
 *  B0-Bn are bots DDoS-ing the network.
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

//Number of Bots for DDoS
#define NUMBER_OF_BOTS 10

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DDoSAttack");

void ApplyAction(uint32_t action, NodeContainer csmaNodesVictim, uint32_t targetNodeId, NodeContainer botNodes) {
    switch (action) {
        case 0: // No attack or stop attack
            // Logic to stop the attack if necessary
            NS_LOG_UNCOND("No attack performed: " << action);
            break;
        case 1: // Perform DDoS attack
        {
            NS_LOG_UNCOND("Performing DDoS attack: " << action);
            Ptr<Node> targetNode = csmaNodesVictim.Get(targetNodeId);
            Address targetAddress = InetSocketAddress(targetNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal(), UDP_SINK_PORT);

            OnOffHelper onoff("ns3::UdpSocketFactory", targetAddress);
            onoff.SetConstantRate(DataRate(DDOS_RATE));
            onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
            onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

            ApplicationContainer onOffApp[NUMBER_OF_BOTS];
            for (int k = 0; k < NUMBER_OF_BOTS; ++k) {
                onOffApp[k] = onoff.Install(botNodes.Get(k));
                onOffApp[k].Start(Seconds(0.0));
                onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
            }
            break;
        }
        default:
            NS_LOG_UNCOND("Invalid action received: " << action);
            break;
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
void Monitor (FlowMonitorHelper *fmh, Ptr<FlowMonitor> fm, NodeContainer csmaNodesVictim, Ptr<Ns3GymEnv> nge, std::unordered_map<std::string, std::vector<double>> flowsDict, NodeContainer botNodes) {
    
    std::string flowId = "";
    double simTime = 0.0;               // Simulation time (elapsed seconds)
    uint32_t srcAddr = 0;               // Source IPv4 address
    uint32_t dstAddr = 0;               // Destination IPv4 address
    uint16_t srcPort = 0;               // Source port
    uint16_t dstPort = 0;               // Destination port
    uint8_t proto = 0;                  // Protocol
    double flowDuration = 0.0;          // Flow duration (Last Tx - First Rx)
    double txPkts = 0;                  // Sent packets
    double rxPkts = 0;                  // Received packets
    double txBytes = 0;                 // Sent bytes
    double rxBytes = 0;                 // Received bytes
    double lostPkts = 0;                // Lost packets
    double throughput = 0.0;            // Throughput (Mbps)
    double totalTxPkts = 0;             // Total sent packets
    double totalRxPkts = 0;             // Total received packets
    double totalTxBytes = 0;            // Total sent bytes
    double totalRxBytes = 0;            // Total received bytes
    double totalFlowDuration = 0.0;     // Total flow duration
    double totalThroughput = 0.0;       // Total throughput (Mbps)
    double totalDelay = 0.0;            // Total delay (s)
    double totalJitter = 0.0;           // Total jitter (s)
    double totalLostPkts = 0;           // Total packets lost
    double pdr = 0.0;                   // Packet Delivery Ratio
    double plr = 0.0;                   // Packet Loss Ratio
    double averageTxPacketSize = 0.0;   // Average transmitted packet size
    double averageRxPacketSize = 0.0;   // Average received packet size
    double averageThroughput = 0.0;     // Average Throughput (Mbps)
    double averageDelay = 0.0;          // Average End to End delay (s)
    double averageJitter = 0.0;         // Average jitter Jitter (s)
    uint32_t activeFlows = 0;           // Active nodes/flows
    
    fm->CheckForLostPackets();

    // Victim Server 1
    Ptr<Node> node_server1 = csmaNodesVictim.Get(1);
    Ptr<Ipv4> ipv4_obj_server1 = node_server1->GetObject<Ipv4>();
    Ipv4Address ipv4_address_server1 = ipv4_obj_server1->GetAddress(1, 0).GetLocal();

    // Obtain stats about the flows
    std::map<FlowId, FlowMonitor::FlowStats> flowStats = fm->GetFlowStats();
    Ptr<Ipv4FlowClassifier> ifc = DynamicCast<Ipv4FlowClassifier>(fmh->GetClassifier());
    
    // Obtain stats about the flows
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator fs = flowStats.begin(); fs != flowStats.end(); ++fs) {
        Ipv4FlowClassifier::FiveTuple ft = ifc->FindFlow(fs->first);
        // Retrieve flow stats for the sink node (Server 1)
        if (ft.destinationAddress == Ipv4Address(ipv4_address_server1)) {
            if (fs->second.rxBytes > 0) {
                activeFlows++;
            }
        }
    }
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator fs = flowStats.begin(); fs != flowStats.end(); ++fs) {
        Ipv4FlowClassifier::FiveTuple ft = ifc->FindFlow(fs->first);
        // Retrieve flow stats for the sink node (Server 1)
        if (ft.destinationAddress == Ipv4Address(ipv4_address_server1)) {
            // Info for the current flow
            simTime = Simulator::Now().GetSeconds();
            srcAddr = Ipv4AddressToInt(ft.sourceAddress);
            dstAddr = Ipv4AddressToInt(ft.destinationAddress);
            srcPort = ft.sourcePort;
            dstPort = ft.destinationPort;
            proto = ft.protocol;
            flowDuration = fs->second.timeLastRxPacket.GetSeconds() - fs->second.timeFirstTxPacket.GetSeconds();
            txPkts = static_cast<double>(fs->second.txPackets);
            rxPkts = static_cast<double>(fs->second.rxPackets);
            txBytes = static_cast<double>(fs->second.txBytes);
            rxBytes = static_cast<double>(fs->second.rxBytes);
            lostPkts = static_cast<double>(fs->second.lostPackets);
            
            // Stats from all the flows
            totalTxPkts += txPkts;
            totalRxPkts += rxPkts;
            totalTxBytes += txBytes;
            totalRxBytes += rxBytes;
            totalFlowDuration += flowDuration;
            throughput = rxBytes * 8.0 / flowDuration / 1024 / 1024;
            totalThroughput += throughput;
            totalDelay += fs->second.delaySum.GetSeconds();
            totalJitter += fs->second.jitterSum.GetSeconds();
            totalLostPkts += lostPkts;
            
            if (totalTxPkts > 0) {
                pdr = totalRxPkts / totalTxPkts;
                plr = totalLostPkts / totalTxPkts;
                averageTxPacketSize = totalTxBytes / totalTxPkts;
            }
            
            if (totalRxPkts > 0) {
                averageDelay = totalDelay / totalRxPkts;
                averageJitter = totalJitter / totalRxPkts;
                averageRxPacketSize = totalRxBytes / totalRxPkts;
            }
            
            if (totalFlowDuration > 0)
                averageThroughput = totalThroughput / totalFlowDuration;

            // Stats for this flow
            flowId = std::to_string(fs->first);
            // Check if there are already stats for this flow, if not, initialise the map object
            if (flowsDict.find(flowId) != flowsDict.end()) {
                flowsDict[flowId][0] += txPkts;
                flowsDict[flowId][1] += rxPkts;
                flowsDict[flowId][2] += txBytes;
                flowsDict[flowId][3] += rxBytes;
                flowsDict[flowId][4] += flowDuration;
                flowsDict[flowId][5] += throughput;
                flowsDict[flowId][6] += fs->second.delaySum.GetSeconds();
                flowsDict[flowId][7] += fs->second.jitterSum.GetSeconds();
                flowsDict[flowId][8] += lostPkts;
                if (flowsDict[flowId][0] > 0) {
                    flowsDict[flowId][9] = flowsDict[flowId][1] / flowsDict[flowId][0];
                    flowsDict[flowId][10] = flowsDict[flowId][8] / flowsDict[flowId][0];
                    flowsDict[flowId][11] = flowsDict[flowId][2] / flowsDict[flowId][0];
                }
                else if (txPkts > 0) {
                    flowsDict[flowId][9] = rxPkts / txPkts;
                    flowsDict[flowId][10] = lostPkts / txPkts;
                    flowsDict[flowId][11] = txBytes / txPkts;
                }
                if (flowsDict[flowId][1] > 0) {
                    flowsDict[flowId][12] = flowsDict[flowId][6] / flowsDict[flowId][1];
                    flowsDict[flowId][13] = flowsDict[flowId][7] / flowsDict[flowId][1];
                    flowsDict[flowId][14] = flowsDict[flowId][3] / flowsDict[flowId][1];
                }
                else if (rxPkts > 0) {
                    flowsDict[flowId][12] = fs->second.delaySum.GetSeconds() / rxPkts;
                    flowsDict[flowId][13] = fs->second.jitterSum.GetSeconds() / rxPkts;
                    flowsDict[flowId][14] = rxBytes / rxPkts;
                }
                if (flowsDict[flowId][4] > 0)
                    flowsDict[flowId][15] = flowsDict[flowId][5] / flowsDict[flowId][4];
                else if (flowDuration > 0)
                    flowsDict[flowId][15] = throughput / flowDuration;
            }
            else {
                std::vector<double> myList;
                flowsDict[flowId] = myList;
                flowsDict[flowId].push_back(txPkts);                                                    // [0] totalTxPkts
                flowsDict[flowId].push_back(rxPkts);                                                    // [1] totalRxPkts
                flowsDict[flowId].push_back(txBytes);                                                   // [2] totalTxBytes
                flowsDict[flowId].push_back(rxBytes);                                                   // [3] totalRxBytes
                flowsDict[flowId].push_back(flowDuration);                                              // [4] totalFlowDuration
                flowsDict[flowId].push_back(throughput);                                                // [5] totalThroughput
                flowsDict[flowId].push_back(fs->second.delaySum.GetSeconds());                          // [6] totalDelay
                flowsDict[flowId].push_back(fs->second.jitterSum.GetSeconds());                         // [7] totalJitter
                flowsDict[flowId].push_back(lostPkts);                                                  // [8] totalLostPkts
                if (txPkts > 0) {
                    flowsDict[flowId].push_back(rxPkts / txPkts);                                       // [9] pdr
                    flowsDict[flowId].push_back(lostPkts / txPkts);                                     // [10] plr
                    flowsDict[flowId].push_back(txBytes / txPkts);                                      // [11] averageTxPacketSize
                }
                else {
                    flowsDict[flowId].push_back(0.0);                                                   // [9] pdr
                    flowsDict[flowId].push_back(0.0);                                                   // [10] plr
                    flowsDict[flowId].push_back(0.0);                                                   // [11] averageTxPacketSize
                }
                if (rxPkts > 0) {
                    flowsDict[flowId].push_back(fs->second.delaySum.GetSeconds() / rxPkts);             // [12] averageDelay
                    flowsDict[flowId].push_back(fs->second.jitterSum.GetSeconds() / rxPkts);            // [13] averageJitter
                    flowsDict[flowId].push_back(rxBytes / rxPkts);                                      // [14] averageRxPacketSize
                }
                else {
                    flowsDict[flowId].push_back(0.0);                                                   // [12] averageDelay
                    flowsDict[flowId].push_back(0.0);                                                   // [13] averageJitter
                    flowsDict[flowId].push_back(0.0);                                                   // [14] averageRxPacketSize
                }
                if (flowDuration > 0)
                    flowsDict[flowId].push_back(throughput / flowDuration);                             // [15] averageThroughput
                else
                    flowsDict[flowId].push_back(0.0);                                                   // [15] averageThroughput
                
            }
            
            // Set the stats to be sent to the Gym env
            nge->SetStats(flowId, simTime, srcAddr, dstAddr, srcPort, dstPort, proto, flowDuration, txPkts, rxPkts, txBytes, rxBytes, lostPkts, throughput,
                          flowsDict, totalTxPkts, totalRxPkts, totalThroughput, totalDelay, totalJitter, totalLostPkts, pdr, plr,
                          averageTxPacketSize, averageRxPacketSize, averageThroughput, averageDelay, averageJitter, activeFlows);

            std::cout << "Flow ID: " << fs->first << " (" << ft.sourceAddress << " -> " << ft.destinationAddress << ")" << std::endl;
            std::cout << "  Simulation time: " << simTime << "s;" << std::endl;
            std::cout << "  Tx Packets: " << txPkts << ";" << std::endl;
            std::cout << "  Rx Packets: " << rxPkts << ";" << std::endl;
            std::cout << "  Avg Tx Packet Size: " << averageTxPacketSize << ";" << std::endl;
            std::cout << "  Avg Rx Packet Size: " << averageRxPacketSize << ";" << std::endl;
            std::cout << "  Flows Packet Delivery Ratio: " << pdr << ";" << std::endl;
            std::cout << "  Flows Packet Loss Ratio: " << plr << ";" << std::endl;
            std::cout << "  Average End-to-End Delay: " << averageDelay << "s;" << std::endl;
            std::cout << "  Average Jitter: " << averageJitter << "s;" << std::endl;
            std::cout << "  Average Throughput: " << averageThroughput << " Mbps;" << std::endl;
            
            // Notify for new flow stats and get action(s) from Gym env
            uint32_t action = nge->NotifyGetAction();
            std::cout << "get_action: " << action << ";" << std::endl;
            
            // Target is Server 1 inside Victim LAN
            ApplyAction(action, csmaNodesVictim, 1, botNodes);
        }
    }
    // Schedule after one second
    Simulator::Schedule(Seconds(1), &Monitor, fmh, fm, csmaNodesVictim, nge, flowsDict, botNodes);
}


int main (int argc, char *argv[])
{
    bool verbose = true;
    uint32_t nCsmaVictim = 10;

    CommandLine cmd;
    cmd.AddValue("nCsma", "Number of \"extra\" CSMA nodes/devices", nCsmaVictim);
    cmd.AddValue("verbose", "Tell echo applications to log if true", verbose);

    cmd.Parse(argc, argv);
    
    // Used to map flows and stats
    std::unordered_map<std::string, std::vector<double>> flowsDict;

    Time::SetResolution(Time::NS);
    if (verbose) {
        LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
        LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    }

    // OpenGym Env --- has to be created before any other thing
    Ptr<OpenGymInterface> openGymInterface = OpenGymInterface::Get();
    Ptr<Ns3GymEnv> nge = CreateObject<Ns3GymEnv>();

    nCsmaVictim = nCsmaVictim == 0 ? 1 : nCsmaVictim;

    // SW Victim (0) and Router/FW Victim (1)
    NodeContainer p2pNodesVictim;
    p2pNodesVictim.Create(2);
    
    // Victim LAN nodes (2 servers and 8 workstations connected to the SW Victim)
    NodeContainer csmaNodesVictim;
    csmaNodesVictim.Add(p2pNodesVictim.Get(0)); // SW Victim (0)
    csmaNodesVictim.Create(nCsmaVictim);        // Servers (1 and 2) and Workstations (3 to 11)
    
    // Internet Router for Attacker and Normal nodes
    NodeContainer p2pNodesInternet;
    p2pNodesInternet.Create(1);
    
    // Nodes for attack bots
    NodeContainer botNodes;
    botNodes.Create(NUMBER_OF_BOTS);
    
    // Nodes for normal clients
    NodeContainer clientNodes;
    clientNodes.Create(1);
    
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
    
    NetDeviceContainer clientDevicesContainer;
    clientDevicesContainer = pp3.Install(p2pNodesInternet.Get(0), clientNodes.Get(0));

    NetDeviceContainer csmaDevicesVictim;
    csmaDevicesVictim = csma.Install(csmaNodesVictim);
    
    InternetStackHelper stack;
    stack.Install(p2pNodesVictim.Get(1));  // FW Victim
    stack.Install(csmaNodesVictim);        // Victim LAN nodes and Router Victim
    stack.Install(p2pNodesInternet);       // Internet Router Attacker/Normal
    stack.Install(clientNodes);            // Clients
    stack.Install(botNodes);               // Bots

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer p2pInterfacesVictim;
    p2pInterfacesVictim = address.Assign(p2pDevicesVictim);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer csmaInterfacesVictim;
    csmaInterfacesVictim = address.Assign(csmaDevicesVictim);
    
    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer p2pInterfacesInternet;
    p2pInterfacesInternet = address.Assign(p2pDevicesInternet);

    address.SetBase("10.0.0.0", "255.255.255.252");
    for (int j = 0; j < NUMBER_OF_BOTS; ++j) {
        address.Assign(botDeviceContainer[j]);
        address.NewNetwork();
    }
    
    address.SetBase("10.0.1.0", "255.255.255.0");
    Ipv4InterfaceContainer clientInterfaces;
    clientInterfaces = address.Assign(clientDevicesContainer);
    
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
    
    // Currently only one server is used in the Victim LAN (node 1)
    // Sender Application (Packets generated by this application are throttled)
    BulkSendHelper bulkSend("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(1), TCP_SINK_PORT));
    bulkSend.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));
    ApplicationContainer bulkSendApp = bulkSend.Install(clientNodes.Get(0));
    bulkSendApp.Start(Seconds(0.0));
    bulkSendApp.Stop(Seconds(MAX_SIMULATION_TIME - 10));
    
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

    ns3::AnimationInterface::SetConstantPosition(clientNodes.Get(0), 45, 5);

    x_pos = 40;
    for (int l = 0; l < NUMBER_OF_BOTS; ++l)
    {
        ns3::AnimationInterface::SetConstantPosition(botNodes.Get(l), x_pos++, 25);
    }
    
    // Monitor the flow(s) and export stats to XML
    FlowMonitorHelper fmh;
    Ptr<FlowMonitor> fm = fmh.InstallAll();
    fm->SerializeToXmlFile("flowmonitor.xml", true, true);
    Monitor(&fmh, fm, csmaNodesVictim, nge, flowsDict, botNodes);

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
