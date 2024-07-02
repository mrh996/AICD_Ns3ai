/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 Technische Universität Berlin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Piotr Gawlowicz <gawlowicz@tkn.tu-berlin.de>
 *
 * Modify: Valerio Selis <v.selis@liverpool.ac.uk>
 * Modify: Ronghui Mu <ronghui.mu@liverpool.ac.uk>
 *
 */

#include "ns3gymenv.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("ns3_gym_env");

NS_OBJECT_ENSURE_REGISTERED (Ns3GymEnv);

/*
Initialise the Gym env and the object's variables
*/
Ns3GymEnv::Ns3GymEnv ()
{
    NS_LOG_FUNCTION (this);
    SetOpenGymInterface(OpenGymInterface::Get());
    
    m_simTime = 0.0;               // 1 - Simulation time (elapsed seconds)
    m_srcAddr = 0;                 // 2 - Source IPv4 address
    m_dstAddr = 0;                 // 3 - Destination IPv4 address
    m_srcPort = 0;                 // 4 - Source port
    m_dstPort= 0;                  // 5 - Destination port
    m_proto = 0;                   // 6 - Protocol
    m_flowDuration = 0.0;          // 7 - Flow duration (Last Tx - First Rx)
    m_txPkts = 0;                  // 8 - Sent packets
    m_rxPkts = 0;                  // 9 - Received packets
    m_txBytes = 0;                 // 10 - Sent bytes
    m_rxBytes = 0;                 // 11 - Received bytes
    m_lostPkts = 0;                // 12 - Lost packets
    m_throughput = 0.0;            // 13 - Throughput (Mbps)
    m_totalTxPkts = 0;             // 14 - Total sent packets
    m_totalRxPkts = 0;             // 15 - Total received packets
    m_totalTxBytes = 0;            // 16 - Total sent bytes
    m_totalRxBytes = 0;            // 17 - Total received bytes
    m_totalFlowDuration = 0.0;     // 18 - Total flow duration
    m_totalThroughput = 0.0;       // 19 - Total throughput (Mbps)
    m_totalDelay = 0.0;            // 20 - Total delay (s)
    m_totalJitter = 0.0;           // 21 - Total jitter (s)
    m_totalLostPkts = 0;           // 22 - Total packets lost
    m_pdr = 0.0;                   // 23 - Packet Delivery Ratio
    m_plr = 0.0;                   // 24 - Packet Loss Ratio
    m_averageTxPacketSize = 0.0;   // 25 - Average transmitted packet size
    m_averageRxPacketSize = 0.0;   // 26 - Average received packet size
    m_averageThroughput = 0.0;     // 27 - Average Throughput (Mbps)
    m_averageDelay = 0.0;          // 28 - Average End to End delay (s)
    m_averageJitter = 0.0;         // 29 - Average jitter Jitter (s)
    m_activeFlows = 0;             // 30 - Active nodes/flows

    m_rxAction = 0;
    m_attackSuccess = false;
    m_cumulativeReward = 0.0;      // Initialize cumulative reward
}

Ns3GymEnv::~Ns3GymEnv ()
{
    NS_LOG_FUNCTION (this);
}

TypeId
Ns3GymEnv::GetTypeId (void)
{
    static TypeId tid = TypeId("ns3::Ns3GymEnv").SetParent<OpenGymEnv>().SetGroupName("Ns3Ai");
    return tid;
}

void
Ns3GymEnv::DoDispose ()
{
    NS_LOG_FUNCTION (this);
}

/*
Callback to define action space
*/
Ptr<OpenGymSpace>
Ns3GymEnv::GetActionSpace()
{
    // m_rxAction
    uint32_t n = 2; // Number of possible actions (0, 1, 2)
    Ptr<OpenGymDiscreteSpace> discrete = CreateObject<OpenGymDiscreteSpace>(n);
    NS_LOG_INFO("Ns3GetActionSpace: " << discrete);
    return discrete;
}

/*
Callback to define observation space
*/
Ptr<OpenGymSpace>
Ns3GymEnv::GetObservationSpace()
{
    uint32_t parameterNum = 30; // Update the number of parameters
    float low = 0.0;            // Minimum value for an item in the box
    float high = 1000000000.0;  // Maximum value for an item in the box
    std::vector<uint32_t> shape = {
        parameterNum,
    };
    std::string dtype = TypeNameGet<double>();

    Ptr<OpenGymBoxSpace> box = CreateObject<OpenGymBoxSpace>(low, high, shape, dtype);
    NS_LOG_INFO("Ns3GetObservationSpace: " << box);
    return box;
}

/*
Callback to define game over condition
*/
bool
Ns3GymEnv::GetGameOver()
{
    NS_LOG_FUNCTION (this);

    // Set the game over condition based on cumulative reward
    bool isGameOver = (m_cumulativeReward >= 20);

    if (isGameOver)
    {
        // Optionally, reset m_attackSuccess and m_cumulativeReward here for the next episode
        m_attackSuccess = false;
        m_cumulativeReward = 0.0; // Reset cumulative reward for the next episode
    }

    NS_LOG_UNCOND("Ns3GetGameOver: " << isGameOver);
    return isGameOver;
}

/*
Callback to collect observations
*/
Ptr<OpenGymDataContainer>
Ns3GymEnv::GetObservation()
{
    NS_LOG_FUNCTION (this);
    // m_rxPackets
    uint32_t parameterNum = 30;
    std::vector<uint32_t> shape = {
        parameterNum,
    };
    Ptr<OpenGymBoxContainer<double>> box = CreateObject<OpenGymBoxContainer<double>>(shape);

    box->AddValue(m_simTime);               // Simulation time (elapsed seconds)
    box->AddValue(m_srcAddr);               // Source IPv4 address
    box->AddValue(m_dstAddr);               // Destination IPv4 address
    box->AddValue(m_srcPort);               // Source port
    box->AddValue(m_dstPort);               // Destination port
    box->AddValue(m_proto);                 // Protocol
    box->AddValue(m_flowDuration);          // Flow duration (Last Tx - First Rx)
    box->AddValue(m_txPkts);                // Sent packets
    box->AddValue(m_rxPkts);                // Received packets
    box->AddValue(m_txBytes);               // Sent bytes
    box->AddValue(m_rxBytes);               // Received bytes
    box->AddValue(m_lostPkts);              // Lost packets
    box->AddValue(m_throughput);            // Throughput (Mbps)
    box->AddValue(m_totalTxPkts);           // Total sent packets
    box->AddValue(m_totalRxPkts);           // Total received packets
    box->AddValue(m_totalTxBytes);          // Total sent bytes
    box->AddValue(m_totalRxBytes);          // Total received bytes
    box->AddValue(m_totalFlowDuration);     // Total flow duration
    box->AddValue(m_totalThroughput);       // Total throughput (Mbps)
    box->AddValue(m_totalDelay);            // Total delay (s)
    box->AddValue(m_totalJitter);           // Total jitter (s)
    box->AddValue(m_totalLostPkts);         // Total packets lost
    box->AddValue(m_pdr);                   // Packet Delivery Ratio
    box->AddValue(m_plr);                   // Packet Loss Ratio
    box->AddValue(m_averageTxPacketSize);   // Average transmitted packet size
    box->AddValue(m_averageRxPacketSize);   // Average received packet size
    box->AddValue(m_averageThroughput);     // Average Throughput (Mbps)
    box->AddValue(m_averageDelay);          // Average End to End delay (s)
    box->AddValue(m_averageJitter);         // Average jitter Jitter (s)
    box->AddValue(m_activeFlows);           // Active nodes/flows
    
    NS_LOG_UNCOND ("Ns3GetObservation: " << box);
    return box;
}

/*
Callback to define reward function
*/
float
Ns3GymEnv::GetReward()
{
    NS_LOG_FUNCTION (this);
    float reward = 0.0;
    if (m_attackSuccess) {
        reward = 10.0; // Reward for successful attack
    } else {
        reward = -1.0; // Penalty for unsuccessful attempts
    }
    m_cumulativeReward += reward; // Update cumulative reward
    NS_LOG_UNCOND("GetReward: " << reward << ", CumulativeReward: " << m_cumulativeReward);
    return reward;
}

/*
Callback to define extra info. Optional
*/
std::string
Ns3GymEnv::GetExtraInfo()
{
    NS_LOG_FUNCTION (this);
    std::string myInfo = "info";
    NS_LOG_UNCOND("Ns3GetExtraInfo: " << myInfo);
    return myInfo;
}

/*
Callback to execute received actions
*/
bool
Ns3GymEnv::ExecuteActions(Ptr<OpenGymDataContainer> action)
{
    // Unpack the actions from the Gym Env (Python)
    //Ptr<OpenGymBoxContainer<uint32_t>> box = DynamicCast<OpenGymBoxContainer<uint32_t>>(action);
    Ptr<OpenGymDiscreteContainer> discrete = DynamicCast<OpenGymDiscreteContainer>(action);
    //uint32_t attackType = box->GetValue(0);
    uint32_t attackType = discrete->GetValue();
    m_rxAction = attackType;

    if (attackType == 1) {
        // Set flag to true indicating that an attack was initiated
        NS_LOG_INFO("Attack sucess: " << attackType);
        m_attackSuccess = true;
    } else {
        m_attackSuccess = false;
    }
    NS_LOG_INFO("ExecuteActions: " << attackType);
    return true;
}

// Setter and getter functions to exhange data with the Gym env

/*
Generate flow stats
*/
void
Ns3GymEnv::SetStats(std::string flowId, double simTime, uint32_t srcAddr, uint32_t dstAddr, uint16_t srcPort,
                    uint16_t dstPort, uint8_t proto, double flowDuration, double txPkts, double rxPkts,
                    double txBytes, double rxBytes, double lostPkts, double throughput,
                    std::unordered_map<std::string, std::vector<double>> flowsDict,
                    double totalTxPkts, double totalRxPkts, double totalThroughput, double totalDelay,
                    double totalJitter, double totalLostPkts, double pdr, double plr,
                    double averageTxPacketSize, double averageRxPacketSize,
                    double averageThroughput, double averageDelay, double averageJitter, uint32_t activeFlows)
{
    m_simTime = simTime;                            // 1 - Simulation time (elapsed seconds)
    m_srcAddr = srcAddr;                            // 2 - Source IPv4 address
    m_dstAddr = dstAddr;                            // 3 - Destination IPv4 address
    m_srcPort = srcPort;                            // 4 - Source port
    m_dstPort = dstPort;                            // 5 - Destination port
    m_proto = proto;                                // 6 - Protocol
    m_flowDuration = flowDuration;                  // 7 - Flow duration (Last Tx - First Rx)
    m_txPkts = txPkts;                              // 8 - Sent packets
    m_rxPkts = rxPkts;                              // 9 - Received packets
    m_txBytes = txBytes;                            // 10 - Sent bytes
    m_rxBytes = rxBytes;                            // 11 - Received bytes
    m_lostPkts = lostPkts;                          // 12 - Lost packets
    m_throughput = throughput;                      // 13 - Throughput (Mbps)
    m_totalTxPkts = flowsDict[flowId][0];           // 14 - Total sent packets
    m_totalRxPkts = flowsDict[flowId][1];           // 15 - Total received packets
    m_totalTxBytes = flowsDict[flowId][2];          // 16 - Total sent bytes
    m_totalRxBytes = flowsDict[flowId][3];          // 17 - Total received bytes
    m_totalFlowDuration = flowsDict[flowId][4];     // 18 - Total flow duration
    m_totalThroughput = flowsDict[flowId][5];       // 19 - Total throughput (Mbps)
    m_totalDelay = flowsDict[flowId][6];            // 20 - Total delay (s)
    m_totalJitter = flowsDict[flowId][7];           // 21 - Total jitter (s)
    m_totalLostPkts = flowsDict[flowId][8];         // 22 - Total packets lost
    m_pdr = flowsDict[flowId][9];                   // 23 - Packet Delivery Ratio
    m_plr = flowsDict[flowId][10];                  // 24 - Packet Loss Ratio
    m_averageTxPacketSize = flowsDict[flowId][11];  // 25 - Average transmitted packet size
    m_averageRxPacketSize = flowsDict[flowId][14];  // 26 - Average received packet size
    m_averageThroughput = flowsDict[flowId][15];    // 27 - Average Throughput (Mbps)
    m_averageDelay = flowsDict[flowId][12];         // 28 - Average End to End delay (s)
    m_averageJitter = flowsDict[flowId][13];        // 29 - Average jitter Jitter (s)
    m_activeFlows = activeFlows;                    // 30 - Active nodes/flows
    
    /*
    m_totalTxPkts = totalTxPkts;
    m_totalRxPkts = totalRxPkts;
    m_totalThroughput = totalThroughput;
    m_totalDelay = totalDelay;
    m_totalJitter = totalJitter;
    m_totalLostPkts = totalLostPkts;
    m_pdr = pdr;
    m_plr = plr;
    m_averageThroughput = averageThroughput;
    m_averageDelay = averageDelay;
    m_averageJitter = averageJitter;
    */
}

/*
Notify for new flow stats and retrieve action(s)
*/
uint32_t
Ns3GymEnv::NotifyGetAction()
{
    // Collects state and send it to the Gym env, receives the action, and executes the callbacks
    Notify();
    return m_rxAction;
}

} // ns3 namespace
