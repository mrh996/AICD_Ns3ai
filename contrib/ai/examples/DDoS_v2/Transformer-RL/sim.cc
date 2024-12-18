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
 *         (SW) ---- (FW) ------------ (Router) ---------- (C1)...(Cm)
 *         (n0)      (n1)               (n12)              (n23)..(n26)
 *      _____|_______                   / |  \
 *     /    / \      \                 /  |   \
 *    /    /   \      \               /   |    \
 *  (S1),(S2),(W1)...(W8)           (B1),(B2)...(Bn)
 *  (n2),(n3),(n4)...(n11)         (n13),(n14)..(n22)
 *
 *                              Attacker Network (Botnet)
 *
 *  S1-S2 are victim servers
 *  W1-W8 are victim workstations
 *  SW is the victim switch managing the Victim LAN composed of servers and workstations
 *  FW is the victim router/firewall
 *  Router is the Internet entry point
 *  C1-Cm are legitimate users, communicating with servers S1 and S2 (data servers), where m=4
 *  B1-Bn are bots DDoS-ing the network, where n=10
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
#include "ns3/random-variable-stream.h"

#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"

#include "ns3/ipv4-l3-protocol.h"
#include "ns3/packet.h"

#include "ns3/packet-metadata.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/trace-helper.h"

#include "ns3gymenv.h"

#include <iostream>
#include <unordered_map>
#include <string>


#define TCP_SINK_PORT 8000
#define UDP_SINK_PORT 9000
#define TCP_INTERNAL_PORT 9500

//Experimental parameters
#define MAX_BULK_BYTES 50000
#define DDOS_RATE "2048000kb/s"
#define MAX_SIMULATION_TIME 10.0

//Number of bots for DDoS
#define NUMBER_OF_BOTS 6
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
bool isBlack;
std::set<Ipv4Address> BlackList;
std::map<Ipv4Address, double> SuspiciousList;
std::map<Ipv4Address, SourceBehaviorStats> sourceBehaviorMap;
uint32_t totalMonitorCount = 0;        // 总的监控次数

bool CustomReceiveCallback(Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol, const Address &from);
NS_LOG_COMPONENT_DEFINE("DDoSAttack");


// void ApplyAction(uint32_t action, uint32_t targetNodeId) {
//     switch (action) {
//         case 0: // No attack or stop attack
//             // Logic to stop the attack if necessary
//             std::cout<< " No attack performed;";
//             NS_LOG_UNCOND("No attack performed: " << action);
//             return;
//         case 1: // Perform DDoS attack
//         {
//             // Ensure that the attack starts after 1 second, starts now+1sec and can be executed (simulation time-1sec)
//             if (Simulator::Now().GetSeconds() > 1.0 && Simulator::Now().GetSeconds() < MAX_SIMULATION_TIME - 1)
//             {
//                 NS_LOG_UNCOND("Performing DDoS attack: " << action);
//                 lastAction = true;
                // Ptr<Node> targetNode = csmaNodesVictim.Get(targetNodeId);
                // Address targetAddress = Address(InetSocketAddress(targetNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal(), 9001));
                // /*std::cout << " Attack node " << targetNode->GetId() 
                //     << "  with address  " << targetNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal() 
                //     << " at " <<Simulator::Now().GetSeconds() <<" s;"<< std::endl;*/
                // OnOffHelper onoff("ns3::UdpSocketFactory", targetAddress);
                // onoff.SetConstantRate(DataRate(DDOS_RATE));
                // onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
                // onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

                // ApplicationContainer onOffApp[NUMBER_OF_BOTS];
                // for (int k = 0; k < NUMBER_OF_BOTS; ++k) {
                //     onOffApp[k] = onoff.Install(botNodes.Get(k));
                //     onOffApp[k].Start(Seconds(Simulator::Now().GetSeconds()+1));
                //     onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
                // }
//                 std::cout << "Action performed" << std::endl;
//                 return;
//             }
//         }
//         default:
//             std::cout<< " Invalid action";
//             NS_LOG_UNCOND("Invalid action received: " << action);
//             return;
//     }
// }

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

void ApplyAction(uint32_t action, std::map<Ipv4Address, SourceBehaviorStats>& sourceBehaviorMap) {
    // Step 1: 统计当前活跃的源地址及其可疑分数
    std::vector<std::pair<Ipv4Address, double>> activeSourceRanking;
    for (const auto& [addr, stats] : sourceBehaviorMap) {
        if (stats.isActive) {
            double dropRate = static_cast<double>(stats.totalDroppedPackets) / stats.totalTxPackets;
            double suspiciousScore = (dropRate > 0.1) 
                ? dropRate * 0.8 + stats.activeRatio 
                : stats.activeRatio;
            activeSourceRanking.push_back({addr, suspiciousScore});
        }
    }

    // 按可疑分数从高到低排序
    std::sort(activeSourceRanking.begin(), activeSourceRanking.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Step 2: 执行动作逻辑
    std::string actionDescription;  // 保存动作描述
    switch (action) {
        case 0: {
            // 不采取任何行动，静默观察
            actionDescription = "Observe (No action taken)";
            break;
        }

        case 1: {
            // 将当前可疑分数最高的前几个源地址加入可疑名单
            int activeCount = activeSourceRanking.size();
            if (activeCount == 0) {
                actionDescription = "Add to Suspicious List (No active sources to add)";
                break;
            }

            int numToAdd = std::max(1, activeCount / 2);
            int count = 0;

            for (const auto& [addr, suspiciousScore] : activeSourceRanking) {
                if (count >= numToAdd) break;

                if (BlackList.find(addr) == BlackList.end() && 
                    SuspiciousList.find(addr) == SuspiciousList.end()) {
                    SuspiciousList.insert({addr, suspiciousScore});
                    count++;
                }
            }
            actionDescription = "Add to Suspicious List (" + std::to_string(count) + " sources added)";
            break;
        }

        case 2: {
            // 从可疑名单中移除当前可疑分数最低的源地址
            if (SuspiciousList.empty()) {
                actionDescription = "Remove from Suspicious List (List is empty)";
                break;
            }

            std::vector<std::pair<Ipv4Address, double>> suspiciousRanking(SuspiciousList.begin(), SuspiciousList.end());
            std::sort(suspiciousRanking.begin(), suspiciousRanking.end(),
                      [](const auto& a, const auto& b) { return a.second < b.second; });

            // 获取可疑分数最低的地址
            Ipv4Address toRemove = suspiciousRanking.front().first;
            double minSuspiciousScore = suspiciousRanking.front().second;

            // 设置可疑分数移除阈值
            const double suspiciousThreshold = 1.0;
            if (minSuspiciousScore > suspiciousThreshold) {
                // 可疑分数过高，拒绝移除
                std::ostringstream oss;
                oss << toRemove;  // 格式化 Ipv4Address
                actionDescription = "Failed to remove from Suspicious List (Address: " + oss.str() + ", Score too high: " + std::to_string(minSuspiciousScore) + ")";
                break;
            }

            // 可疑分数低于阈值，移除该地址
            SuspiciousList.erase(toRemove);
            std::ostringstream oss;
            oss << toRemove;  // 格式化 Ipv4Address
            actionDescription = "Remove from Suspicious List (Address: " + oss.str() + ", Score: " + std::to_string(minSuspiciousScore) + ")";
            break;
        }

        case 3: {
            // 将满足条件的源从可疑名单提升到黑名单
            std::vector<Ipv4Address> toPromote;

            for (const auto& [addr, suspiciousScore] : SuspiciousList) {
                auto& stats = sourceBehaviorMap[addr];
                double dropRate = static_cast<double>(stats.totalDroppedPackets) / stats.totalTxPackets;
                double timeDuration = stats.lastSeenTime - stats.firstSeenTime;
                double TIME_THRESHOLD = 2.0; 

                bool condition1 = stats.isActive &&
                                  timeDuration > TIME_THRESHOLD &&
                                  stats.activeRatio > 0.99;

                bool condition2 = stats.isActive &&
                                  timeDuration > TIME_THRESHOLD &&
                                  dropRate > 0.6;

                if (condition1 || condition2) {
                    toPromote.push_back(addr);
                }
            }

            for (const auto& addr : toPromote) {
                BlackList.insert(addr);
                SuspiciousList.erase(addr);
            }
            actionDescription = "Promote to Blacklist (" + std::to_string(toPromote.size()) + " sources promoted)";
            break;
        }

        default: {
            // 无效的action，什么都不做
            actionDescription = "Invalid Action";
            break;
        }
    }

    // Step 3: 打印当前动作和名单状态
    std::cout << "\n===== Action Taken: " << actionDescription << " =====" << std::endl;

    std::cout << "\n===== Current Suspicious List =====" << std::endl;
    for (const auto& [addr, score] : SuspiciousList) {
        std::cout << "Address: " << addr 
                  << ", Suspicious Score: " << score << std::endl;
    }

    std::cout << "\n===== Current Blacklist =====" << std::endl;
    for (const auto& addr : BlackList) {
        std::cout << "Address: " << addr << std::endl;
    }
    std::cout << "====================================\n" << std::endl;
}



/*
Monitor the flows and exchange info with the Gym env
*/
void Monitor () {
    monitor->CheckForLostPackets();
    double currentSimTime = Simulator::Now().GetSeconds();
    if (currentSimTime >= 0.05) {   // 从第一个time window开始计数
        totalMonitorCount++;  // 总体监控次数增加
    }
    // Victim Server 1
    Ptr<Node> node_server1 = csmaNodesVictim.Get(1);
    Ptr<Ipv4> ipv4_obj_server1 = node_server1->GetObject<Ipv4>();
    Ipv4Address ipv4_address_server1 = ipv4_obj_server1->GetAddress(1, 0).GetLocal();
    
    // Initialize aggregate features for current time window
    AggregateFeatures currentAgg;
    currentAgg.simTime = Simulator::Now().GetSeconds();
    currentAgg.totalTxBytesInc = 0;
    currentAgg.totalRxBytesInc = 0;
    currentAgg.totalTxPacketsInc = 0;
    currentAgg.totalRxPacketsInc = 0; 
    currentAgg.totalDroppedInc = 0;
    currentAgg.avgDelayInc = 0;
    currentAgg.avgJitterInc = 0;
    currentAgg.flowCount = 0;

    // Temporary variables for averaging
    double totalDelay = 0;
    double totalJitter = 0;

    // Obtain stats about the flows
    std::map<FlowId, FlowMonitor::FlowStats> flowStats = monitor->GetFlowStats();
    
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator fs = flowStats.begin(); fs != flowStats.end(); ++fs) {
        Ipv4FlowClassifier::FiveTuple ft = classifier->FindFlow(fs->first);
        // Retrieve flow stats for the sink node (Server 1)
        if (ft.destinationAddress == Ipv4Address(ipv4_address_server1)) {
            // Info for the current flow
            // Stats for this flow
            FlowId flowId = fs->first;
            // Check if there are already stats for this flow, if not, initialise the map object
            if (flowIdFeaturesMap.find(flowId) != flowIdFeaturesMap.end()) {
                flowIdFeaturesMap[flowId].simTime[0] = currentSimTime;
                flowIdFeaturesMap[flowId].timeFirstTxPacket[0] = fs->second.timeFirstTxPacket.GetSeconds();
                flowIdFeaturesMap[flowId].timeLastTxPacket[0] = fs->second.timeLastTxPacket.GetSeconds();
                flowIdFeaturesMap[flowId].timeFirstRxPacket[0] = fs->second.timeFirstRxPacket.GetSeconds();
                flowIdFeaturesMap[flowId].timeLastRxPacket[0] = fs->second.timeLastRxPacket.GetSeconds();
                flowIdFeaturesMap[flowId].txBytes[0] = fs->second.txBytes - flowIdFeaturesMap[flowId].lastTxBytes[0];
                flowIdFeaturesMap[flowId].rxBytes[0] = fs->second.rxBytes - flowIdFeaturesMap[flowId].lastRxBytes[0];
                flowIdFeaturesMap[flowId].txPackets[0] = fs->second.txPackets - flowIdFeaturesMap[flowId].lastTxPackets[0];
                flowIdFeaturesMap[flowId].rxPackets[0] = fs->second.rxPackets - flowIdFeaturesMap[flowId].lastRxPackets[0];
                flowIdFeaturesMap[flowId].droppedPackets[0] = fs->second.lostPackets - flowIdFeaturesMap[flowId].lastLostPackets[0];
                flowIdFeaturesMap[flowId].delaySum[0] = fs->second.delaySum.GetSeconds() - flowIdFeaturesMap[flowId].lastDelaySum[0];;
                flowIdFeaturesMap[flowId].jitterSum[0] = fs->second.jitterSum.GetSeconds() - flowIdFeaturesMap[flowId].lastJitterSum[0];
                // flowIdFeaturesMap[flowId].lastDelay[0] = fs->second.lastDelay.GetSeconds();
                
                // Existing flow - calculate increments
                currentAgg.totalTxBytesInc += flowIdFeaturesMap[flowId].txBytes[0];
                currentAgg.totalRxBytesInc += flowIdFeaturesMap[flowId].rxBytes[0];
                currentAgg.totalTxPacketsInc += flowIdFeaturesMap[flowId].txPackets[0];
                currentAgg.totalRxPacketsInc += flowIdFeaturesMap[flowId].rxPackets[0];
                currentAgg.totalDroppedInc += flowIdFeaturesMap[flowId].droppedPackets[0];
                
                totalDelay += flowIdFeaturesMap[flowId].delaySum[0];
                totalJitter += flowIdFeaturesMap[flowId].jitterSum[0];

                // Update last recorded stats
                flowIdFeaturesMap[flowId].lastTxBytes[0] = fs->second.txBytes;
                flowIdFeaturesMap[flowId].lastRxBytes[0] = fs->second.rxBytes;
                flowIdFeaturesMap[flowId].lastTxPackets[0] = fs->second.txPackets;
                flowIdFeaturesMap[flowId].lastRxPackets[0] = fs->second.rxPackets;
                flowIdFeaturesMap[flowId].lastLostPackets[0] = fs->second.lostPackets;
                flowIdFeaturesMap[flowId].lastDelaySum[0] = fs->second.delaySum.GetSeconds();
                flowIdFeaturesMap[flowId].lastJitterSum[0] = fs->second.jitterSum.GetSeconds();
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
                flowIdFeaturesMap[flowId].droppedPackets.push_back(fs->second.lostPackets);
                flowIdFeaturesMap[flowId].delaySum.push_back(fs->second.delaySum.GetSeconds());
                flowIdFeaturesMap[flowId].jitterSum.push_back(fs->second.jitterSum.GetSeconds());
                // flowIdFeaturesMap[flowId].lastDelay.push_back(fs->second.lastDelay.GetSeconds());
                
                // Add initial values to aggregates
                currentAgg.totalTxBytesInc += flowIdFeaturesMap[flowId].txBytes[0];
                currentAgg.totalRxBytesInc += flowIdFeaturesMap[flowId].rxBytes[0];
                currentAgg.totalTxPacketsInc += flowIdFeaturesMap[flowId].txPackets[0];
                currentAgg.totalRxPacketsInc += flowIdFeaturesMap[flowId].rxPackets[0];
                currentAgg.totalDroppedInc += flowIdFeaturesMap[flowId].droppedPackets[0];
                
                totalDelay += flowIdFeaturesMap[flowId].delaySum[0];
                totalJitter += flowIdFeaturesMap[flowId].jitterSum[0];

                flowIdFeaturesMap[flowId].lastTxBytes.push_back(fs->second.txBytes);
                flowIdFeaturesMap[flowId].lastRxBytes.push_back(fs->second.rxBytes);
                flowIdFeaturesMap[flowId].lastTxPackets.push_back(fs->second.txPackets);
                flowIdFeaturesMap[flowId].lastRxPackets.push_back(fs->second.rxPackets);
                flowIdFeaturesMap[flowId].lastLostPackets.push_back(fs->second.lostPackets);
                flowIdFeaturesMap[flowId].lastDelaySum.push_back(fs->second.delaySum.GetSeconds());
                flowIdFeaturesMap[flowId].lastJitterSum.push_back(fs->second.jitterSum.GetSeconds());
            }
            // Don't include dropped packets statistics if source address is in blacklist or suspicious list
            if (BlackList.find(ft.sourceAddress) != BlackList.end() || 
                SuspiciousList.find(ft.sourceAddress) != SuspiciousList.end()) {
                currentAgg.totalDroppedInc = 0;  // Set dropped packet count to 0 for these addresses 
            }
            auto& stats = sourceBehaviorMap[ft.sourceAddress];
            stats.isActive = false;
            // For new source address
            if (stats.firstSeenTime == 0) {
                stats.firstSeenTime = flowIdFeaturesMap[flowId].timeFirstTxPacket[0];
                stats.activeCount = 0;
                stats.totalTxBytes = 0;
                stats.totalTxPackets = 0;
                stats.firstMonitorCount = totalMonitorCount;
            }
            
            // Update active count and data statistics only when there's actual data transmission
            if (flowIdFeaturesMap[flowId].txBytes[0] > 0 || 
                flowIdFeaturesMap[flowId].rxBytes[0] > 0) {
                currentAgg.flowCount++;
                
                // Update activity-related statistics
                stats.activeCount++;  
                stats.isActive = true;          
                stats.lastSeenTime = flowIdFeaturesMap[flowId].timeLastTxPacket[0];
                stats.totalTxBytes += flowIdFeaturesMap[flowId].txBytes[0];
                stats.totalTxPackets += flowIdFeaturesMap[flowId].txPackets[0];
                stats.totalDroppedPackets += flowIdFeaturesMap[flowId].droppedPackets[0]; 
                
                // Calculate average sending rate
                double duration = stats.lastSeenTime - stats.firstSeenTime;
                if (duration > 0) {
                    stats.avgSendRate = static_cast<double>(stats.totalTxBytes) / duration;
               }
            }
            
            // Calculate active ratio (updated every monitoring interval)
            stats.activeRatio = static_cast<double>(stats.activeCount) / (totalMonitorCount - stats.firstMonitorCount + 1);
        }
    }
    // Calculate averages only when there are active flows
    if (currentAgg.flowCount > 0) {
        currentAgg.avgDelayInc = totalDelay / currentAgg.flowCount;
        currentAgg.avgJitterInc = totalJitter / currentAgg.flowCount;
    }else{
        currentAgg.avgDelayInc = 0;
        currentAgg.avgJitterInc = 0;
    }
    // Print statistics for all source addresses before aggregate data
    std::cout << "\n===== All Source Addresses Statistics =====" << std::endl;
    std::cout << "Total Monitor Count: " << totalMonitorCount << std::endl;
    for (const auto& sourcePair : sourceBehaviorMap) {
        const auto& sourceAddr = sourcePair.first;
        const auto& stats = sourcePair.second;
        
        std::cout << "\nSource Address: " << sourceAddr
                << "\nFirst Seen at: " << stats.firstSeenTime
                << "\nLast Seen at: " << stats.lastSeenTime
                << "\nActive Count: " << stats.activeCount
                << "\nActive Ratio: " << stats.activeRatio
                << "\nActive Status: " << stats.isActive
                << "\n(active " << stats.activeCount << " times in " 
                << (totalMonitorCount - stats.firstMonitorCount + 1) << " monitors)"
                << "\nTotal Tx Bytes: " << stats.totalTxBytes
                << "\nTotal Tx Packets: " << stats.totalTxPackets
                << "\nTotal Dropped Packets: " << stats.totalDroppedPackets
                << "\nAvg Send Rate: " << stats.avgSendRate << " bytes/s"
                << "\nDuration: " << (stats.lastSeenTime - stats.firstSeenTime) << "s"
                << std::endl;
    }
    std::cout << "========================================================\n" << std::endl;
    bool isSuspiciousListEmpty = SuspiciousList.empty();
    nge->SetStats(currentAgg, isSuspiciousListEmpty);

    // Get action from Gym environment
    uint32_t action = nge->NotifyGetAction();
    // action = 0;

    ApplyAction(action, sourceBehaviorMap);
    // std::cout << "\n===== Aggregate Network Statistics at Time " << currentAgg.simTime << "s =====" << std::endl;
    // std::cout << "Active Flows: " << currentAgg.flowCount << std::endl;
    // std::cout << "Total Tx Bytes (increment): " << currentAgg.totalTxBytesInc << " bytes" << std::endl;
    // std::cout << "Total Rx Bytes (increment): " << currentAgg.totalRxBytesInc << " bytes" << std::endl;
    // std::cout << "Total Tx Packets (increment): " << currentAgg.totalTxPacketsInc << " packets" << std::endl;
    // std::cout << "Total Rx Packets (increment): " << currentAgg.totalRxPacketsInc << " packets" << std::endl;
    // std::cout << "Total Dropped Packets (increment): " << currentAgg.totalDroppedInc << " packets" << std::endl;
    // std::cout << "Average Delay (increment): " << currentAgg.avgDelayInc << " seconds" << std::endl;
    // std::cout << "Average Jitter (increment): " << currentAgg.avgJitterInc << " seconds" << std::endl;
    // std::cout << "========================================================\n" << std::endl;

    Simulator::Schedule(Seconds(0.05), &Monitor);
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

    // std::cout << std::endl << "NodeID: " << nodeID << " - " << eventType << " - FlowId: " << nodeIdFeaturesMap[nodeID].flowId[flowIndex] 
    //             << " - Sim Time: " << nodeIdFeaturesMap[nodeID].simTime[flowIndex] 
    //             << " - Source IP: " << ipv4Header.GetSource() << " - " << nodeIdFeaturesMap[nodeID].srcAddr[flowIndex] 
    //             << " - Destination IP: " << ipv4Header.GetDestination() << " - " << nodeIdFeaturesMap[nodeID].dstAddr[flowIndex]
    //             << " - Source Port: " << nodeIdFeaturesMap[nodeID].srcPort[flowIndex] 
    //             << " - Destination Port: " << nodeIdFeaturesMap[nodeID].dstPort[flowIndex]
    //             << " - Protocol: " << static_cast<uint32_t>(nodeIdFeaturesMap[nodeID].proto[flowIndex])
    //             << " - Tx bytes: " << nodeIdFeaturesMap[nodeID].txBytes[flowIndex] 
    //             << " - Rx bytes: " << nodeIdFeaturesMap[nodeID].rxBytes[flowIndex] 
    //             << " - Tx Packets: " << nodeIdFeaturesMap[nodeID].txPackets[flowIndex] 
    //             << " - Rx Packets: " << nodeIdFeaturesMap[nodeID].rxPackets[flowIndex] 
    //             << " - Forwarded Packets: " << nodeIdFeaturesMap[nodeID].forwardedPackets[flowIndex] 
    //             << " - Dropped Packets: " << nodeIdFeaturesMap[nodeID].droppedPackets[flowIndex] 
    //             << " - Delay: " << nodeIdFeaturesMap[nodeID].delaySum[flowIndex] 
    //             << " - Jitter: " << nodeIdFeaturesMap[nodeID].jitterSum[flowIndex]  << std::endl;


    // // Set the stats to be sent to the Gym env
    // std::cout << "Send dict to Gym env for nodeid " << nodeID << "   flowid " << flowId << std::endl;
    // std::cout << "Extract features - Simulation time: " << currentSimTime << " s;" << std::endl;
    // nge->SetStats(nodeID, flowId, flowIndex, nodeIdFeaturesMap);

    // // // // Notify for new flow stats and get action(s) from Gym env
    // uint32_t action = nge->NotifyGetAction();
    // std::cout << "Extract features - get_action: " << action << ";" << std::endl;    
    // ApplyAction(action, Ipv4Address("0.0.0.0"));
}


bool CustomReceiveCallback(Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol, const Address &from)
{
    // Get IPv4 Protocal
    Ptr<Ipv4> ipv4 = device->GetNode()->GetObject<Ipv4>();

    // Get Source address and destination address
    Ptr<Packet> packetCopy = packet->Copy();
    Ipv4Header ipv4Header;
    packetCopy->RemoveHeader(ipv4Header);
    Ipv4Address sourceAddress = ipv4Header.GetSource();
    Ipv4Address destAddress = ipv4Header.GetDestination();

    // std::cout << "Packet received from: " << sourceAddress 
    //           << " to: " << destAddress << std::endl;

    // Firewall: Block addresses in both BlackList and SuspiciousList
    for (const auto& filterAddress : BlackList)
    {   
        if (sourceAddress == filterAddress)
        {
            // std::cout <<  "Packet from blacklisted address " << sourceAddress << " filtered" << std::endl;
            return false; 
        }
    }

    for (const auto& filterAddress : SuspiciousList)
    {   
        if (sourceAddress == filterAddress.first)  // SuspiciousList contains address-score pairs
        {
            // std::cout <<  "Packet from suspicious address " << sourceAddress << " filtered" << std::endl;
            return false; 
        }
    }

    // Forward the packet if not blocked
    Ptr<Ipv4L3Protocol> ipv4L3 = ipv4->GetObject<Ipv4L3Protocol>();
    ipv4L3->Receive(device, packet, protocol, from, Address(destAddress), NetDevice::PACKET_HOST);

    return true;
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
    // filterAddressList.push_back(Ipv4Address("10.0.1.2"));
    // filterAddressList.push_back(Ipv4Address("10.0.2.2"));
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
    clientNodes.Create(NUMBER_OF_CLIENTS);
    
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
    
    // dummy attack server 1 (node 2)
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(csmaInterfacesVictim.GetAddress(1), 9001)));
    onoff.SetConstantRate(DataRate(DDOS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp[NUMBER_OF_BOTS];
    
    // Install application in all bots
    for (int k = 0; k < NUMBER_OF_BOTS; ++k) {
        onOffApp[k] = onoff.Install(botNodes.Get(k));

        if (k < 2) {
            onOffApp[k].Start(Seconds(0.0));
            onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
        } else {
            onOffApp[k].Start(Seconds(5.0));
            onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
        }
    }

    std::vector<ApplicationContainer> bulkSendApps1;  // Store applications for client 1
    std::vector<ApplicationContainer> bulkSendApps2;  // Store applications for client 2
    std::vector<ApplicationContainer> bulkSendApps3;  // Store applications for client 3
    std::vector<ApplicationContainer> bulkSendApps4;  // Store applications for client 4

    // Configure transmission timing for client 1
    std::vector<double> startTimes1 = {0.2, 2.0, 4.0};  // Start times for client 1
    std::vector<double> durations1 = {1.0, 1.0, 1.0};   // Durations for client 1
    std::vector<uint32_t> sendBytes1 = {50000, 50000, 50000};  // Bytes to send for client 1

    // Configure different transmission timing for client 2
    std::vector<double> startTimes2 = {0.5, 2.5, 6.0};  // Start times for client 2
    std::vector<double> durations2 = {1.0, 1.0, 1.0};    // Durations for client 2
    std::vector<uint32_t> sendBytes2 = {50000, 50000, 50000};   // Bytes to send for client 2

    // Configure different transmission timing for client 3
    std::vector<double> startTimes3 = {1.5, 6.5};  // Start times for client 3
    std::vector<double> durations3 = {1.0, 1.0};    // Durations for client 3
    std::vector<uint32_t> sendBytes3 = {50000, 50000};   // Bytes to send for client 3

    // Configure different transmission timing for client 4
    std::vector<double> startTimes4 = {3.5, 8.5};  // Start times for client 4
    std::vector<double> durations4 = {1.0, 1.0};    // Durations for client 4
    std::vector<uint32_t> sendBytes4 = {50000, 50000};   // Bytes to send for client 4

    // Set Client 1
    for(size_t i = 0; i < startTimes1.size(); i++) {
        BulkSendHelper bulkSendServer1("ns3::TcpSocketFactory", 
            InetSocketAddress(csmaInterfacesVictim.GetAddress(1), 8001));
        bulkSendServer1.SetAttribute("MaxBytes", UintegerValue(sendBytes1[i]));
        
        ApplicationContainer app1 = bulkSendServer1.Install(clientNodes.Get(0));
        app1.Start(Seconds(startTimes1[i]));
        app1.Stop(Seconds(startTimes1[i] + durations1[i]));
        bulkSendApps1.push_back(app1);
    }

    // Set Client 2
    for(size_t i = 0; i < startTimes2.size(); i++) {
        BulkSendHelper bulkSendServer2("ns3::TcpSocketFactory", 
            InetSocketAddress(csmaInterfacesVictim.GetAddress(1), 8001));
        bulkSendServer2.SetAttribute("MaxBytes", UintegerValue(sendBytes2[i]));
        
        ApplicationContainer app2 = bulkSendServer2.Install(clientNodes.Get(1));
        app2.Start(Seconds(startTimes2[i]));
        app2.Stop(Seconds(startTimes2[i] + durations2[i]));
        bulkSendApps2.push_back(app2);
    }
    
    // Set Client 3
    for(size_t i = 0; i < startTimes3.size(); i++) {
        BulkSendHelper bulkSendServer3("ns3::TcpSocketFactory", 
            InetSocketAddress(csmaInterfacesVictim.GetAddress(1), 8001));
        bulkSendServer3.SetAttribute("MaxBytes", UintegerValue(sendBytes3[i]));
        
        ApplicationContainer app3 = bulkSendServer3.Install(clientNodes.Get(2));
        app3.Start(Seconds(startTimes3[i]));
        app3.Stop(Seconds(startTimes3[i] + durations3[i]));
        bulkSendApps3.push_back(app3);
    }
    
    // Set Client 4
    for(size_t i = 0; i < startTimes4.size(); i++) {
        BulkSendHelper bulkSendServer4("ns3::TcpSocketFactory", 
            InetSocketAddress(csmaInterfacesVictim.GetAddress(1), 8001));
        bulkSendServer4.SetAttribute("MaxBytes", UintegerValue(sendBytes4[i]));
        
        ApplicationContainer app4 = bulkSendServer4.Install(clientNodes.Get(3));
        app4.Start(Seconds(startTimes4[i]));
        app4.Stop(Seconds(startTimes4[i] + durations4[i]));
        bulkSendApps4.push_back(app4);
    }
    // Legitimate client connection to Server 1 in the Victim LAN (node 2)
    // Sender Application (Packets generated by this application are throttled)
    // BulkSendHelper bulkSendServer1("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(1), 8001));
    // bulkSendServer1.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));
    // ApplicationContainer bulkSendServer1App1 = bulkSendServer1.Install(clientNodes.Get(0)); // Legitimate client 1
    // ApplicationContainer bulkSendServer1App2 = bulkSendServer1.Install(clientNodes.Get(1)); // Legitimate client 2
    // // ApplicationContainer bulkSendServer1App3 = bulkSendServer1.Install(csmaNodesVictim.Get(3)); // Victim workstation 1
    // // ApplicationContainer bulkSendServer1App4 = bulkSendServer1.Install(csmaNodesVictim.Get(4)); // Victim workstation 2
    // bulkSendServer1App1.Start(Seconds(0.2));
    // bulkSendServer1App1.Stop(Seconds(MAX_SIMULATION_TIME - 3));
    // bulkSendServer1App2.Start(Seconds(0.1));
    // bulkSendServer1App2.Stop(Seconds(MAX_SIMULATION_TIME - 2));
    // bulkSendServer1App3.Start(Seconds(1.0));
    // bulkSendServer1App3.Stop(Seconds(5.0));
    // bulkSendServer1App4.Start(Seconds(1.1));
    // bulkSendServer1App4.Stop(Seconds(6.0));

    // // Legitimate client connections to Server 2 in the Victim LAN (node 3)
    // // Sender Application (Packets generated by this application are throttled)
    // BulkSendHelper bulkSendServer2("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(2), 8002));
    // bulkSendServer2.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));
    // ApplicationContainer bulkSendServer2App1 = bulkSendServer2.Install(clientNodes.Get(2)); // Legitimate client 3
    // ApplicationContainer bulkSendServer2App2 = bulkSendServer2.Install(clientNodes.Get(3)); // Legitimate client 4
    // ApplicationContainer bulkSendServer2App3 = bulkSendServer2.Install(csmaNodesVictim.Get(5)); // Victim workstation 3
    // ApplicationContainer bulkSendServer2App4 = bulkSendServer2.Install(csmaNodesVictim.Get(6)); // Victim workstation 4
    // bulkSendServer2App1.Start(Seconds(0.1));
    // bulkSendServer2App1.Stop(Seconds(MAX_SIMULATION_TIME - 1));
    // bulkSendServer2App2.Start(Seconds(1.0));
    // bulkSendServer2App2.Stop(Seconds(MAX_SIMULATION_TIME - 1));
    // bulkSendServer2App3.Start(Seconds(2.0));
    // bulkSendServer2App3.Stop(Seconds(5.0));
    // bulkSendServer2App4.Start(Seconds(3.0));
    // bulkSendServer2App4.Stop(Seconds(6.0));


    // client send TCP traffic to all victim nodes randomly
    // for (uint32_t clientIndex = 0; clientIndex < clientNodes.GetN(); ++clientIndex) {
    //     // for (uint32_t victimIndex = 1; victimIndex < csmaNodesVictim.GetN(); ++victimIndex) {
    //         // Set Address and Port
    //         BulkSendHelper tcpClient("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(1), TCP_SINK_PORT + 1));
    //         tcpClient.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));

    //         // start time
    //         Ptr<UniformRandomVariable> randomStartTime = CreateObject<UniformRandomVariable>();
    //         randomStartTime->SetAttribute("Min", DoubleValue(0.0));
    //         randomStartTime->SetAttribute("Max", DoubleValue(MAX_SIMULATION_TIME - 2.0));
    //         double startTime = randomStartTime->GetValue();

    //         // interval time
    //         Ptr<UniformRandomVariable> randomInterval = CreateObject<UniformRandomVariable>();
    //         randomInterval->SetAttribute("Min", DoubleValue(1.0));
    //         randomInterval->SetAttribute("Max", DoubleValue(MAX_SIMULATION_TIME - startTime));
    //         double interval = randomInterval->GetValue();

    //         double stopTime = startTime + interval;
    //         if (stopTime > MAX_SIMULATION_TIME) {
    //             stopTime = MAX_SIMULATION_TIME;
    //         }

    //         install TCP sender to all client nodes
    //         ApplicationContainer tcpClientApp = tcpClient.Install(clientNodes.Get(clientIndex));
    //         tcpClientApp.Start(Seconds(0.0));
    //         tcpClientApp.Stop(Seconds(5.0));
    //     }
    // }
    

    // // Add random TCP traffic generation between victim nodes within Victim LAN
    // for (uint32_t victimSenderInnerIndex = 1; victimSenderInnerIndex < csmaNodesVictim.GetN(); ++victimSenderInnerIndex) {
    //     Ptr<UniformRandomVariable> randomVictimInnerIndex = CreateObject<UniformRandomVariable>();
    //     randomVictimInnerIndex->SetAttribute("Min", DoubleValue(1.0));
    //     randomVictimInnerIndex->SetAttribute("Max", DoubleValue(csmaNodesVictim.GetN() - 1));

    //     // Randomly select a different victim node to communicate with
    //     uint32_t victimReceiverInnerIndex;
    //     do {
    //         victimReceiverInnerIndex = randomVictimInnerIndex->GetInteger();
    //     } while (victimReceiverInnerIndex == victimSenderInnerIndex); // Ensure a node doesn't send to itself

    //     // Set up TCP communication between victim nodes
    //     BulkSendHelper tcpClientInner("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(victimReceiverInnerIndex), TCP_SINK_PORT + victimReceiverInnerIndex));
    //     tcpClientInner.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));

    //     // Start time for the client application
    //     Ptr<UniformRandomVariable> randomStartTimeInner = CreateObject<UniformRandomVariable>();
    //     randomStartTimeInner->SetAttribute("Min", DoubleValue(0.0));
    //     randomStartTimeInner->SetAttribute("Max", DoubleValue(MAX_SIMULATION_TIME - 2.0));
    //     double startTimeInner = randomStartTimeInner->GetValue();

    //     // Interval time
    //     Ptr<UniformRandomVariable> randomIntervalInner = CreateObject<UniformRandomVariable>();
    //     randomIntervalInner->SetAttribute("Min", DoubleValue(1.0));
    //     randomIntervalInner->SetAttribute("Max", DoubleValue(MAX_SIMULATION_TIME - startTimeInner));
    //     double intervalInner = randomIntervalInner->GetValue();
        
    //     double stopTimeInner = startTimeInner + intervalInner;
    //     if (stopTimeInner > MAX_SIMULATION_TIME) {
    //         stopTimeInner = MAX_SIMULATION_TIME;
    //     }

    //     // Install TCP sender to the selected victim node
    //     ApplicationContainer tcpClientAppInner = tcpClientInner.Install(csmaNodesVictim.Get(victimSenderInnerIndex));
    //     tcpClientAppInner.Start(Seconds(startTimeInner));
    //     tcpClientAppInner.Stop(Seconds(stopTimeInner));
    // }
    
    for (uint32_t victimIndex = 1; victimIndex < csmaNodesVictim.GetN(); ++victimIndex) {
        // install TCP sink: 
        PacketSinkHelper tcpSink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), TCP_SINK_PORT + victimIndex));
        ApplicationContainer tcpSinkApp = tcpSink.Install(csmaNodesVictim.Get(victimIndex));
        tcpSinkApp.Start(Seconds(0.0));
        tcpSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));

        // install UDP sink
        PacketSinkHelper udpSink("ns3::UdpSocketFactory", Address(InetSocketAddress(Ipv4Address::GetAny(), UDP_SINK_PORT + victimIndex)));
        ApplicationContainer udpSinkApp = udpSink.Install(csmaNodesVictim.Get(victimIndex));
        udpSinkApp.Start(Seconds(0.0));
        udpSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));
    }

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
    
    classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());

    // Attach the callback to trace packets passing through the nodes within the victim network
    // for (uint32_t i = 0; i < p2pNodesVictim.GetN(); ++i)
    // {   
    //         Ptr<Ipv4> ipv4 = p2pNodesVictim.Get(i)->GetObject<Ipv4>();
    //         ipv4->TraceConnectWithoutContext("Tx", MakeCallback(&TxPacketTraceCallback));
    //         ipv4->TraceConnectWithoutContext("Rx", MakeCallback(&RxPacketTraceCallback));
    // }
    for (uint32_t i = 0; i < p2pNodesVictim.GetN(); ++i)
    {
        Ptr<Ipv4> ipv4 = p2pNodesVictim.Get(i)->GetObject<Ipv4>();
        bool isRouter = (i == 1);

        if (isRouter)
        {   
            // Check Router
            for (uint32_t j = 0; j < ipv4->GetNInterfaces(); ++j)
            {
                Ipv4InterfaceAddress iaddr = ipv4->GetAddress(j, 0);
                std::cout << "Node " << i << " has IP address " << iaddr.GetLocal() << " on interface " << j << std::endl;
            }

            // Implement filtering
            Ptr<NetDevice> deviceInternet = ipv4->GetNetDevice(2);  // Interface 2：connect internet
            if (deviceInternet)
            {
                std::cout << "Setting receive callback for device at interface index 2" << std::endl;
                deviceInternet->SetReceiveCallback(MakeCallback(&CustomReceiveCallback));
            }
        }

        // If no filtering, still trace packets
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

    // Ensures the simulator stops eventually
    Simulator::Stop(Seconds(MAX_SIMULATION_TIME + 5));
    Simulator::Run();
    
    monitor->SerializeToXmlFile("flowmonitor.xml", true, true);
    openGymInterface->NotifySimulationEnd();
    
    Simulator::Destroy();
    return 0;
}

    