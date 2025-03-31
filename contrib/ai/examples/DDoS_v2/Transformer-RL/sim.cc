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
 *         (n0)      (n1)               (n12)              (n21)..(n50)
 *      _____|_______                   / |  \
 *     /    / \      \                 /  |   \
 *    /    /   \      \               /   |    \
 *  (S1),(S2),(W1)...(W8)           (B1),(B2)...(Bn)
 *  (n2),(n3),(n4)...(n11)         (n13),(n14)..(n20)
 *
 *                              Attacker Network (Botnet)
 *
 *  S1-S2 are victim servers
 *  W1-W8 are victim workstations
 *  SW is the victim switch managing the Victim LAN composed of servers and workstations
 *  FW is the victim router/firewall
 *  Router is the Internet entry point
 *  C1-Cm are legitimate users, communicating with servers S1 and S2 (data servers), where m=4
 *  B1-Bn are bots DDoS-ing the network, where n=8
 *
 * NetAnim XML is saved as -> DDoSim.xml
 *
 * 2025 University of Liverpool
 * Modify: Valerio Selis <v.selis@liverpool.ac.uk>
 * Modify: Ronghui Mu <ronghui.mu@liverpool.ac.uk>
 * Modify: Jinwei Hu <jinwei.hu@liverpool.ac.uk>
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
#include <random>
#include <iostream>
#include <unordered_map>
#include <string>


#define TCP_SINK_PORT 8000
#define UDP_SINK_PORT 9000
#define TCP_INTERNAL_PORT 9500

//Experimental parameters
#define MAX_BULK_BYTES 50000
#define DDOS_RATE "204800kb/s"
// 7 for training, 10.5 for testing
#define MAX_SIMULATION_TIME 10.5

//Number of bots for DDoS
#define NUMBER_OF_BOTS 60
//Number of legitimate clients
#define NUMBER_OF_CLIENTS 200

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

Ipv4InterfaceContainer botInterfaces;  // store the interfaces of the bot nodes

// Used to determine if an attack has been performed
bool lastAction;
bool testSuspiciousSuccess = 0;
bool promoteBlackSuccess = 0;
std::set<Ipv4Address> BlackList;
std::map<Ipv4Address, double> SuspiciousList;
std::map<Ipv4Address, SourceBehaviorStats> sourceBehaviorMap;
uint32_t totalMonitorCount = 0;        // total monitor count

bool CustomReceiveCallback(Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol, const Address &from);
NS_LOG_COMPONENT_DEFINE("DDoSAttack");


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
    // Step 1: compute suspicious score based on rules

    const double DECAY_RATE = 0.9;  // decay rate
    std::vector<std::pair<Ipv4Address, double>> activeSourceRanking;

    for (const auto& [addr, stats] : sourceBehaviorMap) {
        if (stats.isActive) {
            double dropRate = static_cast<double>(stats.totalDroppedPackets) / stats.totalTxPackets;
            double suspiciousScore = (dropRate > 0.1) 
                ? dropRate * 0.8 + stats.activeRatio 
                : stats.activeRatio;
                
            activeSourceRanking.push_back({addr, suspiciousScore});
            
            // update the suspicious score for active sources
            auto it = SuspiciousList.find(addr);
            if (it != SuspiciousList.end()) {
                it->second = suspiciousScore;  // update the score
            }
        } else {
            // decay the suspicious score for inactive sources
            auto it = SuspiciousList.find(addr);
            if (it != SuspiciousList.end()) {
                it->second *= DECAY_RATE;  
            }
        }
    }

    // sort by suspicious score
    std::sort(activeSourceRanking.begin(), activeSourceRanking.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Step 2: symbolic actions
    std::string actionDescription;  
    switch (action) {
        case 0: {
            // observe
            actionDescription = "Observe (No action taken)";
            break;
        }

        case 1: {
            // add to Suspicious List
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
                    if (suspiciousScore < 0.2){
                        std::cout << "\n===== Push Failed due to low suspicious score (< 0.2): " << addr << " =====" << std::endl;
                        continue; 
                    }
                    SuspiciousList.insert({addr, suspiciousScore});
                    count++;
                }
            }
            actionDescription = "Add to Suspicious List (" + std::to_string(count) + " sources added)";
            break;
        }

        case 2: {
            // remove from Suspicious List
            if (SuspiciousList.empty()) {
                actionDescription = "Remove from Suspicious List (List is empty)";
                break;
            }

            std::vector<std::pair<Ipv4Address, double>> suspiciousRanking(SuspiciousList.begin(), SuspiciousList.end());
            std::sort(suspiciousRanking.begin(), suspiciousRanking.end(),
                      [](const auto& a, const auto& b) { return a.second < b.second; });

            // get the address with the lowest suspicious score
            Ipv4Address toRemove = suspiciousRanking.front().first;
            double minSuspiciousScore = suspiciousRanking.front().second;

            // set a threshold for removing from the list
            const double suspiciousThreshold = 1.0;
            if (minSuspiciousScore > suspiciousThreshold) {
                // refuse to remove
                std::ostringstream oss;
                oss << toRemove;  
                actionDescription = "Failed to remove from Suspicious List (Address: " + oss.str() + ", Score too high: " + std::to_string(minSuspiciousScore) + ")";
                testSuspiciousSuccess = 0;
                break;
            }

            // remove from Suspicious List
            SuspiciousList.erase(toRemove);
            testSuspiciousSuccess = 1;
            std::ostringstream oss;
            oss << toRemove;  
            actionDescription = "Remove from Suspicious List (Address: " + oss.str() + ", Score: " + std::to_string(minSuspiciousScore) + ")";
            break;
        }

        case 3: {
            // promote to blacklist
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
                    promoteBlackSuccess = 1;
                } else {
                    promoteBlackSuccess = 0;
                }
            }

            for (const auto& addr : toPromote) {
                BlackList.insert(addr);
                SuspiciousList.erase(addr);
            }
            
            ApplicationContainer newContainer;
            for (int k = 0; k < NUMBER_OF_BOTS; ++k) {
                Ptr<Node> node = botNodes.Get(k);

                // get Bot IP
                Ipv4Address botIp = botInterfaces.GetAddress(k);
                std::cout << "[INFO] Checking bot " << k << " with IP: " << botIp << std::endl;

                // Check if the bot is in the blacklist
                if (BlackList.find(botIp) != BlackList.end()) {
                    std::cout << "Blacklisted bot detected: " << botIp << std::endl;

                    // get OnOffApplication
                    Ptr<Application> app = node->GetApplication(0);
                    Ptr<OnOffApplication> onOffApp = DynamicCast<OnOffApplication>(app);

                    if (onOffApp) {
                        std::cout << "Stopping attack from bot: " << botIp << std::endl;
                        
                        // stop OnOffApplication
                        newContainer.Add(onOffApp);
                        newContainer.Stop(Seconds(Simulator::Now().GetSeconds() + 0.1));

                        std::cout << "Attack stopped for bot with IP " << botIp << std::endl;
                    } else {
                        std::cout << "Failed to retrieve OnOffApplication for bot: " << botIp << std::endl;
                    }
                }
            }



            actionDescription = "Promote to Blacklist (" + std::to_string(toPromote.size()) + " sources promoted)";
            break;
        }

        default: {
            actionDescription = "Invalid Action";
            break;
        }
    }

    // Step 3: print
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

void ApplyLLMAction(uint32_t action, std::map<Ipv4Address, SourceBehaviorStats>& sourceBehaviorMap) {
    // Step 1: compute suspicious score based on rules with adaptive parameters
    
    // Adaptive decay rate based on network size and activity
    const double BASE_DECAY_RATE = 0.9;
    double activeSourceCount = 0;
    for (const auto& [addr, stats] : sourceBehaviorMap) {
        if (stats.isActive) activeSourceCount++;
    }
    
    // Adjust decay rate based on network activity - slower decay in high-activity environments
    const double DECAY_RATE = std::max(0.7, BASE_DECAY_RATE - (activeSourceCount / 500.0));
    
    // Dynamic suspicious score threshold that adapts to environment scale
    const double BASE_SUSPICIOUS_THRESHOLD = 0.2;
    const double SUSPICIOUS_THRESHOLD = BASE_SUSPICIOUS_THRESHOLD * (1.0 - std::min(0.5, activeSourceCount / 300.0));
    
    // Activity window adjustment - shorter window for larger environments to enable faster reaction
    const double TIME_THRESHOLD = std::max(1.0, 2.0 * (1.0 - std::min(0.5, activeSourceCount / 300.0)));
    
    std::vector<std::pair<Ipv4Address, double>> activeSourceRanking;
    
    // Enhanced suspicious score calculation with weighted packet drop rate
    for (const auto& [addr, stats] : sourceBehaviorMap) {
        if (stats.isActive) {
            // More sophisticated drop rate calculation with packet volume consideration
            double dropRate = static_cast<double>(stats.totalDroppedPackets) / std::max(1.0, static_cast<double>(stats.totalTxPackets));
            double packetVolumeFactor = std::min(1.0, stats.totalTxPackets / 1000.0); // Normalize large packet volumes
            
            // Weighted suspicious score calculation with rate limiting factor
            double suspiciousScore = 0.0;
            if (dropRate > 0.1) {
                // High drop rate sources
                suspiciousScore = (dropRate * 0.7) + 
                                 (stats.activeRatio * 0.2) + 
                                 (packetVolumeFactor * 0.1);
            } else {
                // Low drop rate sources - focus more on activity patterns
                suspiciousScore = (stats.activeRatio * 0.8) + 
                                 (packetVolumeFactor * 0.2);
            }
            
            activeSourceRanking.push_back({addr, suspiciousScore});
            
            // Update the suspicious score for active sources with exponential moving average
            auto it = SuspiciousList.find(addr);
            if (it != SuspiciousList.end()) {
                // Apply EMA to smooth score updates
                const double ALPHA = 0.3; // EMA factor
                it->second = (ALPHA * suspiciousScore) + ((1.0 - ALPHA) * it->second);
            }
        } else {
            // Decay the suspicious score for inactive sources
            auto it = SuspiciousList.find(addr);
            if (it != SuspiciousList.end()) {
                it->second *= DECAY_RATE;
                
                // Remove from suspicious list if score decays below removal threshold
                if (it->second < 0.05) {
                    SuspiciousList.erase(it);
                }
            }
        }
    }
    
    // Sort by suspicious score
    std::sort(activeSourceRanking.begin(), activeSourceRanking.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Step 2: symbolic actions with improved logic
    std::string actionDescription;
    switch (action) {
        case 0: {
            // Observe - now with proactive intelligence gathering
            // Track suspicious patterns even during observation
            if (!activeSourceRanking.empty() && activeSourceRanking.front().second > 0.8) {
                // Auto-flag extremely suspicious sources during observation
                const auto& [addr, score] = activeSourceRanking.front();
                if (BlackList.find(addr) == BlackList.end() && 
                    SuspiciousList.find(addr) == SuspiciousList.end()) {
                    SuspiciousList.insert({addr, score});
                    actionDescription = "Observe with Auto-Flag (1 source flagged due to high score: " + 
                                      std::to_string(score) + ")";
                } else {
                    actionDescription = "Observe (No action taken)";
                }
            } else {
                actionDescription = "Observe (No action taken)";
            }
            break;
        }
        
        case 1: {
            // Add to Suspicious List with improved selection criteria
            int activeCount = activeSourceRanking.size();
            if (activeCount == 0) {
                actionDescription = "Add to Suspicious List (No active sources to add)";
                break;
            }
            
            // Scale number to add based on environment size
            int numToAdd = std::max(1, std::min(activeCount / 3, 30)); // Cap at 10 to prevent list explosion
            int count = 0;
            
            // Track suspicious behaviors individually
            std::vector<std::string> addedDetails;
            
            for (const auto& [addr, suspiciousScore] : activeSourceRanking) {
                if (count >= numToAdd) break;
                
                if (BlackList.find(addr) == BlackList.end() && 
                    SuspiciousList.find(addr) == SuspiciousList.end()) {
                    
                    // Apply dynamic threshold based on network activity
                    if (suspiciousScore < SUSPICIOUS_THRESHOLD) {
                        std::cout << "\n===== Push Failed due to low suspicious score (< " << 
                                SUSPICIOUS_THRESHOLD << "): " << addr << " =====" << std::endl;
                        continue;
                    }
                    
                    // Add to suspicious list with current score
                    SuspiciousList.insert({addr, suspiciousScore});
                    
                    // Create log entry for this addition
                    std::ostringstream logEntry;
                    logEntry << addr << " (score: " << suspiciousScore << ")";
                    addedDetails.push_back(logEntry.str());
                    
                    count++;
                }
            }
            
            actionDescription = "Add to Suspicious List (" + std::to_string(count) + " sources added)";
            
            // Log detailed information about additions
            if (!addedDetails.empty()) {
                std::cout << "\n===== Added to Suspicious List =====" << std::endl;
                for (const auto& detail : addedDetails) {
                    std::cout << "  - " << detail << std::endl;
                }
            }
            
            break;
        }
        
        case 2: {
            // Remove from Suspicious List with improved criteria
            if (SuspiciousList.empty()) {
                actionDescription = "Remove from Suspicious List (List is empty)";
                break;
            }
            
            // Enhanced prioritization for removal
            std::vector<std::pair<Ipv4Address, double>> removalCandidates;
            
            // Identify sources to potentially remove
            for (const auto& [addr, suspiciousScore] : SuspiciousList) {
                auto it = sourceBehaviorMap.find(addr);
                
                if (it == sourceBehaviorMap.end()) {
                    // Source no longer exists in behavior map - likely disappeared
                    removalCandidates.push_back({addr, -1.0}); // Priority removal
                    continue;
                }
                
                const auto& stats = it->second;
                
                // If inactive for a while, prioritize for removal
                if (!stats.isActive) {
                    double inactiveTime = Simulator::Now().GetSeconds() - stats.lastSeenTime;
                    if (inactiveTime > 5.0) {
                        removalCandidates.push_back({addr, 0.0}); // Inactive removal
                        continue;
                    }
                }
                
                // Low suspicious score sources
                if (suspiciousScore < 0.3) {
                    removalCandidates.push_back({addr, suspiciousScore});
                }
            }
            
            // If we have candidates for removal
            if (!removalCandidates.empty()) {
                // Sort by score (lowest first, missing/inactive prioritized)
                std::sort(removalCandidates.begin(), removalCandidates.end(),
                        [](const auto& a, const auto& b) { return a.second < b.second; });
                
                // Get up to 3 addresses with the lowest suspicious score
                int removeCount = std::min(static_cast<int>(removalCandidates.size()), 10);
                std::vector<std::string> removedDetails;
                
                for (int i = 0; i < removeCount; i++) {
                    Ipv4Address toRemove = removalCandidates[i].first;
                    double score = removalCandidates[i].second;
                    
                    // Skip if score is above threshold and not missing/inactive
                    if (score > 0.6 && score != -1.0 && score != 0.0) {
                        continue;
                    }
                    
                    // Generate removal reason string
                    std::string reason;
                    if (score == -1.0) {
                        reason = "source disappeared";
                    } else if (score == 0.0) {
                        reason = "source inactive";
                    } else {
                        reason = "low score: " + std::to_string(score);
                    }
                    
                    // Remove from Suspicious List
                    SuspiciousList.erase(toRemove);
                    testSuspiciousSuccess = 1;
                    
                    // Log details
                    std::ostringstream oss;
                    oss << toRemove << " (" << reason << ")";
                    removedDetails.push_back(oss.str());
                }
                
                if (!removedDetails.empty()) {
                    actionDescription = "Remove from Suspicious List (" + std::to_string(removedDetails.size()) + " sources removed)";
                    
                    std::cout << "\n===== Removed from Suspicious List =====" << std::endl;
                    for (const auto& detail : removedDetails) {
                        std::cout << "  - " << detail << std::endl;
                    }
                } else {
                    actionDescription = "Remove from Suspicious List (No suitable candidates for removal)";
                    testSuspiciousSuccess = 0;
                }
            } else {
                actionDescription = "Remove from Suspicious List (No suitable candidates for removal)";
                testSuspiciousSuccess = 0;
            }
            
            break;
        }
        
        case 3: {
            // Promote to blacklist with improved detection criteria
            std::vector<Ipv4Address> toPromote;
            std::vector<std::string> promotionDetails;
            
            // Enhanced prioritization to handle larger environments
            for (const auto& [addr, suspiciousScore] : SuspiciousList) {
                auto it = sourceBehaviorMap.find(addr);
                
                // Skip if not in behavior map
                if (it == sourceBehaviorMap.end()) continue;
                
                const auto& stats = it->second;
                
                // Skip if not active
                if (!stats.isActive) continue;
                
                double dropRate = static_cast<double>(stats.totalDroppedPackets) / 
                                 std::max(1.0, static_cast<double>(stats.totalTxPackets));
                
                double timeDuration = stats.lastSeenTime - stats.firstSeenTime;
                
                // Adjust thresholds based on activity level
                double dynamicTimeThreshold = TIME_THRESHOLD;
                double dynamicDropRateThreshold = 0.6 - (activeSourceCount / 1000.0); // Lower in larger environments
                double dynamicActiveRatioThreshold = 0.95; // Slightly lowered from 0.99
                
                // Promotion criteria
                bool condition1 = timeDuration > dynamicTimeThreshold && 
                                stats.activeRatio > dynamicActiveRatioThreshold;
                
                bool condition2 = timeDuration > dynamicTimeThreshold && 
                                dropRate > dynamicDropRateThreshold;
                
                // New condition for sustained high suspicious score
                bool condition3 = suspiciousScore > 0.85 && 
                                timeDuration > dynamicTimeThreshold * 1.5;
                
                // Packet volume-based condition for high-traffic attackers
                bool condition4 = stats.totalTxPackets > 5000 && 
                                dropRate > dynamicDropRateThreshold * 0.8 &&
                                timeDuration > dynamicTimeThreshold * 0.5;
                
                if (condition1 || condition2 || condition3 || condition4) {
                    toPromote.push_back(addr);
                    
                    // Create detailed reason for promotion
                    std::ostringstream reason;
                    reason << addr << " (";
                    if (condition1) reason << "high activity ratio: " << stats.activeRatio;
                    else if (condition2) reason << "high drop rate: " << dropRate;
                    else if (condition3) reason << "sustained high score: " << suspiciousScore;
                    else if (condition4) reason << "high volume attack: " << stats.totalTxPackets << " packets";
                    reason << ")";
                    
                    promotionDetails.push_back(reason.str());
                    promoteBlackSuccess = 1;
                } else {
                    promoteBlackSuccess = 0;
                }
            }
            
            for (const auto& addr : toPromote) {
                BlackList.insert(addr);
                SuspiciousList.erase(addr);
            }
            
            // Blacklist enforcement with rate limiting to prevent processing overload
            ApplicationContainer newContainer;
            int enforcementCount = 0; 
            const int MAX_ENFORCEMENTS_PER_CYCLE = 10; // Limit enforcements per cycle
            
            for (int k = 0; k < NUMBER_OF_BOTS && enforcementCount < MAX_ENFORCEMENTS_PER_CYCLE; ++k) {
                Ptr<Node> node = botNodes.Get(k);
                
                // Get Bot IP
                Ipv4Address botIp = botInterfaces.GetAddress(k);
                
                // Check if the bot is in the blacklist
                if (BlackList.find(botIp) != BlackList.end()) {
                    std::cout << "Blacklisted bot detected: " << botIp << std::endl;
                    
                    // Get OnOffApplication
                    Ptr<Application> app = node->GetApplication(0);
                    Ptr<OnOffApplication> onOffApp = DynamicCast<OnOffApplication>(app);
                    
                    if (onOffApp) {
                        std::cout << "Stopping attack from bot: " << botIp << std::endl;
                        
                        // Stop OnOffApplication
                        newContainer.Add(onOffApp);
                        newContainer.Stop(Seconds(Simulator::Now().GetSeconds() + 0.1));
                        
                        std::cout << "Attack stopped for bot with IP " << botIp << std::endl;
                        enforcementCount++;
                    } else {
                        std::cout << "Failed to retrieve OnOffApplication for bot: " << botIp << std::endl;
                    }
                }
            }
            
            actionDescription = "Promote to Blacklist (" + std::to_string(toPromote.size()) + " sources promoted)";
            
            // Log detailed promotion information
            if (!promotionDetails.empty()) {
                std::cout << "\n===== Promoted to Blacklist =====" << std::endl;
                for (const auto& detail : promotionDetails) {
                    std::cout << "  - " << detail << std::endl;
                }
            }
            
            break;
        }
        
        default: {
            actionDescription = "Invalid Action";
            break;
        }
    }
    
    // Step 3: print status with improved metrics
    std::cout << "\n===== Action Taken: " << actionDescription << " =====" << std::endl;
    
    // Print current suspicious list with score-based coloring
    std::cout << "\n===== Current Suspicious List (" << SuspiciousList.size() << " entries) =====" << std::endl;
    if (SuspiciousList.empty()) {
        std::cout << "  (empty)" << std::endl;
    } else {
        // Sort by score for better readability
        std::vector<std::pair<Ipv4Address, double>> sortedSuspicious(SuspiciousList.begin(), SuspiciousList.end());
        std::sort(sortedSuspicious.begin(), sortedSuspicious.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (const auto& [addr, score] : sortedSuspicious) {
            std::string riskLevel;
            if (score > 0.8) riskLevel = "HIGH";
            else if (score > 0.5) riskLevel = "MEDIUM";
            else riskLevel = "LOW";
            
            std::cout << "Address: " << addr 
                    << ", Suspicious Score: " << score 
                    << " [" << riskLevel << "]" << std::endl;
        }
    }
    
    // Print current blacklist
    std::cout << "\n===== Current Blacklist (" << BlackList.size() << " entries) =====" << std::endl;
    if (BlackList.empty()) {
        std::cout << "  (empty)" << std::endl;
    } else {
        for (const auto& addr : BlackList) {
            std::cout << "Address: " << addr << std::endl;
        }
    }
    
    // Print key metrics
    std::cout << "\n===== Current Environment Metrics =====" << std::endl;
    std::cout << "Active Sources: " << activeSourceCount << std::endl;
    std::cout << "Dynamic Suspicious Threshold: " << SUSPICIOUS_THRESHOLD << std::endl;
    std::cout << "Dynamic Time Threshold: " << TIME_THRESHOLD << std::endl;
    std::cout << "====================================\n" << std::endl;
}



/*
Monitor the flows and exchange info with the Gym env
*/
void Monitor () {
    monitor->CheckForLostPackets();
    double currentSimTime = Simulator::Now().GetSeconds();
    if (currentSimTime >= 0.1) {   // Start monitoring
        totalMonitorCount++;  // total monitor count
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
                // currentAgg.totalTxBytesInc += flowIdFeaturesMap[flowId].txBytes[0];
                // currentAgg.totalRxBytesInc += flowIdFeaturesMap[flowId].rxBytes[0];
                // currentAgg.totalTxPacketsInc += flowIdFeaturesMap[flowId].txPackets[0];
                // currentAgg.totalRxPacketsInc += flowIdFeaturesMap[flowId].rxPackets[0];
                // Don't include dropped packets statistics if source address is in blacklist or suspicious list
                if (BlackList.find(ft.sourceAddress) == BlackList.end() && 
                    SuspiciousList.find(ft.sourceAddress) == SuspiciousList.end()) {
                    currentAgg.totalTxBytesInc += flowIdFeaturesMap[flowId].txBytes[0];
                    currentAgg.totalRxBytesInc += flowIdFeaturesMap[flowId].rxBytes[0];
                    currentAgg.totalTxPacketsInc += flowIdFeaturesMap[flowId].txPackets[0];
                    currentAgg.totalRxPacketsInc += flowIdFeaturesMap[flowId].rxPackets[0];
                    currentAgg.totalDroppedInc += flowIdFeaturesMap[flowId].droppedPackets[0];  // Set dropped packet count to 0 for these addresses 
                }
                
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
                // currentAgg.totalTxBytesInc += flowIdFeaturesMap[flowId].txBytes[0];
                // currentAgg.totalRxBytesInc += flowIdFeaturesMap[flowId].rxBytes[0];
                // currentAgg.totalTxPacketsInc += flowIdFeaturesMap[flowId].txPackets[0];
                // currentAgg.totalRxPacketsInc += flowIdFeaturesMap[flowId].rxPackets[0];
                // Don't include dropped packets statistics if source address is in blacklist or suspicious list
                if (BlackList.find(ft.sourceAddress) == BlackList.end() && 
                    SuspiciousList.find(ft.sourceAddress) == SuspiciousList.end()) {
                    currentAgg.totalTxBytesInc += flowIdFeaturesMap[flowId].txBytes[0];
                    currentAgg.totalRxBytesInc += flowIdFeaturesMap[flowId].rxBytes[0];
                    currentAgg.totalTxPacketsInc += flowIdFeaturesMap[flowId].txPackets[0];
                    currentAgg.totalRxPacketsInc += flowIdFeaturesMap[flowId].rxPackets[0];
                    currentAgg.totalDroppedInc += flowIdFeaturesMap[flowId].droppedPackets[0];  // Set dropped packet count to 0 for these addresses 
                }
                
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
            auto& stats = sourceBehaviorMap[ft.sourceAddress];
            stats.isActive = false;
            // For new source address
            if (stats.firstSeenTime == 0) {
                stats.firstSeenTime = flowIdFeaturesMap[flowId].timeFirstTxPacket[0];
                stats.activeCount = 0;
                stats.totalTxBytes = 0;
                stats.totalTxPackets = 0;
                stats.totalRxBytes = 0;
                stats.totalRxPackets = 0;
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
                stats.totalRxBytes += flowIdFeaturesMap[flowId].rxBytes[0];
                stats.totalRxPackets += flowIdFeaturesMap[flowId].rxPackets[0];
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
                << "\nTotal Rx Bytes: " << stats.totalRxBytes
                << "\nTotal Rx Packets: " << stats.totalRxPackets
                << "\nTotal Dropped Packets: " << stats.totalDroppedPackets
                << "\nAvg Send Rate: " << stats.avgSendRate << " bytes/s"
                << "\nDuration: " << (stats.lastSeenTime - stats.firstSeenTime) << "s"
                << std::endl;
    }
    std::cout << "========================================================\n" << std::endl;
    bool isSuspiciousListEmpty = SuspiciousList.empty();
    nge->SetStats(currentAgg, isSuspiciousListEmpty, testSuspiciousSuccess, promoteBlackSuccess);

    // Get action from Gym environment
    uint32_t action = nge->NotifyGetAction();
    // action = 0;

    ApplyLLMAction(action, sourceBehaviorMap); 
    // monitor frequency
    Simulator::Schedule(Seconds(0.1), &Monitor);
}

void extract_features(Ptr<const Packet> packet, uint32_t nodeID, const std::string &eventType) {
    // Create a copy of the packet to parse it
    Ptr<Packet> packetCopy = packet->Copy();

    uint32_t packetBytes = packetCopy->GetSize();                       // Packet bytes
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
        UdpHeader udpHeader;
        packetCopy->RemoveHeader(udpHeader);
        srcPort = udpHeader.GetSourcePort();
        dstPort = udpHeader.GetDestinationPort();
        t.sourcePort = udpHeader.GetSourcePort();
        t.destinationPort = udpHeader.GetDestinationPort();
    }
    // Extract info from the TCP header
    else if(proto == TcpL4Protocol::PROT_NUMBER) {
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
        Ipv4InterfaceContainer temp = address.Assign(botDeviceContainer[j]);  
        botInterfaces.Add(temp.Get(1));  
        address.NewNetwork();  
    }
 
    address.SetBase("10.0.1.0", "255.255.255.0");
    for (int j = 0; j < NUMBER_OF_CLIENTS; ++j) {
        address.Assign(clientDevicesContainer[j]);
        address.NewNetwork();
    }

    // Create random variable generator
    Ptr<UniformRandomVariable> randomTime = CreateObject<UniformRandomVariable>();

    // dummy attack server 1 (node 2)
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(csmaInterfacesVictim.GetAddress(1), 9001)));
    onoff.SetConstantRate(DataRate(DDOS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp[NUMBER_OF_BOTS];

    // Install application in all bots
    for (int k = 0; k < NUMBER_OF_BOTS; ++k) {
        onOffApp[k] = onoff.Install(botNodes.Get(k));
        
        // Generate random start times for different groups
        double startTime;
        if (k < 12) {
            startTime = randomTime->GetValue(0.0, 2.0); 
        } else if (k >= 12 && k < 22) {
            startTime = randomTime->GetValue(2.0, 4.0);  
        } else if (k >= 22 && k < 34) {
            startTime = randomTime->GetValue(4.0, 5.0);  
        } else if (k >= 34 && k < 48) {
            startTime = randomTime->GetValue(5.0, 6.0);  
        } else if (k >= 48 && k <= 55) {
            startTime = randomTime->GetValue(6.0, 8.0); 
        } else {
            startTime = randomTime->GetValue(8.0, 9.5);  
        }
        
        onOffApp[k].Start(Seconds(startTime));
        onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
    }

    const uint32_t numTransmissions = 10; // Number of transmissions per client: train
    const double minStartTime = 0.0;  // Minimum start time
    const double maxStartTime = MAX_SIMULATION_TIME - 0.5; // Maximum start time
    const double duration = 1.0;      // Duration for each transmission
    const uint32_t sendBytes = 2000; // Bytes to send per transmission
    std::vector<ApplicationContainer> bulkSendApps; // Store all application containers

    // Random number generator setup
    std::random_device rd;
    std::mt19937 gen(rd()); // random number generator
    std::uniform_real_distribution<> timeDist(minStartTime, maxStartTime);

    for (uint32_t clientId = 0; clientId < NUMBER_OF_CLIENTS; clientId++) {
        std::vector<double> startTimes; // Store random start times for this client

        // Generate random start times for the client
        for (uint32_t i = 0; i < numTransmissions; i++) {
            double randomTime = timeDist(gen);
            startTimes.push_back(randomTime);
        }

        // Sort start times to ensure sequential scheduling
        std::sort(startTimes.begin(), startTimes.end());

        // Configure transmissions for this client
        for (uint32_t i = 0; i < numTransmissions; i++) {
            BulkSendHelper bulkSendHelper("ns3::TcpSocketFactory",
                InetSocketAddress(csmaInterfacesVictim.GetAddress(1), 8001));
            bulkSendHelper.SetAttribute("MaxBytes", UintegerValue(sendBytes));

            ApplicationContainer app = bulkSendHelper.Install(clientNodes.Get(clientId));
            app.Start(Seconds(startTimes[i]));
            app.Stop(Seconds(startTimes[i] + duration));
            bulkSendApps.push_back(app);
        }
    }

    // client send TCP traffic to all victim nodes randomly
    for (uint32_t clientIndex = 0; clientIndex < clientNodes.GetN(); ++clientIndex) {
        for (uint32_t victimIndex = 1; victimIndex < csmaNodesVictim.GetN(); ++victimIndex) {
            // Set Address and Port
            BulkSendHelper tcpClient("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(1), TCP_SINK_PORT + 1));
            tcpClient.SetAttribute("MaxBytes", UintegerValue(sendBytes));

            // start time
            Ptr<UniformRandomVariable> randomStartTime = CreateObject<UniformRandomVariable>();
            randomStartTime->SetAttribute("Min", DoubleValue(0.0));
            randomStartTime->SetAttribute("Max", DoubleValue(MAX_SIMULATION_TIME - 2.0));
            double startTime = randomStartTime->GetValue();

            double stopTime = startTime + 1;
            if (stopTime > MAX_SIMULATION_TIME) {
                stopTime = MAX_SIMULATION_TIME;
            }

            // install TCP sender to all client nodes
            ApplicationContainer tcpClientApp = tcpClient.Install(clientNodes.Get(clientIndex));
            tcpClientApp.Start(Seconds(startTime));
            tcpClientApp.Stop(Seconds(stopTime));
        }
    }
    

    // Add random TCP traffic generation between victim nodes within Victim LAN
    for (uint32_t victimSenderInnerIndex = 1; victimSenderInnerIndex < csmaNodesVictim.GetN(); ++victimSenderInnerIndex) {
        Ptr<UniformRandomVariable> randomVictimInnerIndex = CreateObject<UniformRandomVariable>();
        randomVictimInnerIndex->SetAttribute("Min", DoubleValue(1.0));
        randomVictimInnerIndex->SetAttribute("Max", DoubleValue(csmaNodesVictim.GetN() - 1));

        // Randomly select a different victim node to communicate with
        uint32_t victimReceiverInnerIndex;
        do {
            victimReceiverInnerIndex = randomVictimInnerIndex->GetInteger();
        } while (victimReceiverInnerIndex == victimSenderInnerIndex); // Ensure a node doesn't send to itself

        // Set up TCP communication between victim nodes
        BulkSendHelper tcpClientInner("ns3::TcpSocketFactory", InetSocketAddress(csmaInterfacesVictim.GetAddress(victimReceiverInnerIndex), TCP_SINK_PORT + victimReceiverInnerIndex));
        tcpClientInner.SetAttribute("MaxBytes", UintegerValue(sendBytes));

        // Start time for the client application
        Ptr<UniformRandomVariable> randomStartTimeInner = CreateObject<UniformRandomVariable>();
        randomStartTimeInner->SetAttribute("Min", DoubleValue(0.0));
        randomStartTimeInner->SetAttribute("Max", DoubleValue(MAX_SIMULATION_TIME - 2.0));
        double startTimeInner = randomStartTimeInner->GetValue();

        // Interval time
        Ptr<UniformRandomVariable> randomIntervalInner = CreateObject<UniformRandomVariable>();
        randomIntervalInner->SetAttribute("Min", DoubleValue(1.0));
        randomIntervalInner->SetAttribute("Max", DoubleValue(MAX_SIMULATION_TIME - startTimeInner));
        double intervalInner = randomIntervalInner->GetValue();
        
        double stopTimeInner = startTimeInner + intervalInner;
        if (stopTimeInner > MAX_SIMULATION_TIME) {
            stopTimeInner = MAX_SIMULATION_TIME;
        }

        // Install TCP sender to the selected victim node
        ApplicationContainer tcpClientAppInner = tcpClientInner.Install(csmaNodesVictim.Get(victimSenderInnerIndex));
        tcpClientAppInner.Start(Seconds(startTimeInner));
        tcpClientAppInner.Stop(Seconds(stopTimeInner));
    }
    
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
    Simulator::Stop(Seconds(MAX_SIMULATION_TIME));
    Simulator::Run();
    
    monitor->SerializeToXmlFile("flowmonitor.xml", true, true);
    openGymInterface->NotifySimulationEnd();
    
    Simulator::Destroy();
    return 0;
}
