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
    m_nodeId = 0;
    m_flowId = 0;
    m_simTime = 0;               // Simulation time (elapsed seconds)
    m_srcAddr = 0;             // Source IPv4 address
    m_dstAddr = 0;             // Destination IPv4 address
    m_srcPort = 0;             // Source port
    m_dstPort = 0;             // Destination port
    m_proto = 0;                // Protocol
    m_timeFirstTxPacket = 0;
    m_timeLastTxPacket = 0;
    m_timeFirstRxPacket = 0;
    m_timeLastRxPacket = 0;
    m_txBytes = 0;               // Sent bytes
    m_rxBytes = 0;               // Received bytes
    m_txPkts = 0;                // Sent packets
    m_rxPkts = 0;                // Received packets
    m_forwardedPackets = 0;
    m_droppedPackets = 0;
    m_delaySum = 0;
    m_jitterSum = 0;
    m_lastDelay = 0;
    m_throughput = 0;            // Throughput (Mbps)
    m_flowDuration = 0;          // Flow duration (Last Tx - First Rx)
    m_pdr = 0;                   // Packet Delivery Ratio
    m_plr = 0;                   // Packet Loss Ratio
    m_averageTxPacketSize = 0;   // Average transmitted packet size
    m_averageRxPacketSize = 0;   // Average received packet size

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
    uint32_t parameterNum = 27; // Update the number of parameters
    float low = -1.0;            // Minimum value in the box
    float high = 1000000000.0;  // Maximum value in the box
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
    bool isGameOver = (m_cumulativeReward >= 20000);

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
    uint32_t parameterNum = 27;
    std::vector<uint32_t> shape = {
        parameterNum,
    };
    Ptr<OpenGymBoxContainer<double>> box = CreateObject<OpenGymBoxContainer<double>>(shape);

    std::cout << "GetObs nodeId " << m_nodeId << "  Sim Time " << m_simTime << " s" << std::endl;

    box->AddValue(m_nodeId);                // 1 - Node ID (number if info from a node, -1 if overall info of a flow)
    box->AddValue(m_flowId);                // 2 - Flow ID
    box->AddValue(m_simTime);               // 3 - Simulation time (elapsed seconds)
    box->AddValue(m_srcAddr);               // 4 - Source IPv4 address
    box->AddValue(m_dstAddr);               // 5 - Destination IPv4 address
    box->AddValue(m_srcPort);               // 6 - Source port
    box->AddValue(m_dstPort);               // 7 - Destination port
    box->AddValue(m_proto);                 // 8 - Protocol
    box->AddValue(m_timeFirstTxPacket);     // 9 - Time of the first TX packet (s)
    box->AddValue(m_timeLastTxPacket);      // 10 - Time of the last TX packet (s)
    box->AddValue(m_timeFirstRxPacket);     // 11 - Time of the first RX packet (s)
    box->AddValue(m_timeLastRxPacket);      // 12 - Time of the last RX packet (s)
    box->AddValue(m_txBytes);               // 13 - Sent bytes
    box->AddValue(m_rxBytes);               // 14 - Received bytes
    box->AddValue(m_txPkts);                // 15 - Sent packets
    box->AddValue(m_rxPkts);                // 16 - Received packets
    box->AddValue(m_forwardedPackets);      // 17 - Number of forwarded packets
    box->AddValue(m_droppedPackets);        // 18 - Number of forwarded packets
    box->AddValue(m_delaySum);              // 19 - Total delay (s)
    box->AddValue(m_jitterSum);             // 20 - Total jitter (s)
    box->AddValue(m_lastDelay);             // 21 - Last delay value (s)
    box->AddValue(m_throughput);            // 22 - Throughput (Mbps)
    box->AddValue(m_flowDuration);          // 23 - Flow duration (Last Tx - First Rx)
    box->AddValue(m_pdr);                   // 24 - Packet Delivery Ratio
    box->AddValue(m_plr);                   // 25 - Packet Loss Ratio
    box->AddValue(m_averageTxPacketSize);   // 26 - Average transmitted packet size (B)
    box->AddValue(m_averageRxPacketSize);   // 27 - Average received packet size (B)
    
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
        reward = 1.0;  // Reward for successful attack
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
Ns3GymEnv::SetStats(int nodeId, int flowId, int flowIndex, FeaturesMap& featuresMap)
{
    std::cout << "Set stats for nodeid " << nodeId << "   flowIndex " << flowIndex << std::endl;
    if (nodeId == -1) {
        /*
        std::cout << std::endl << "nodeId: " << nodeId << " - FlowId: " << featuresMap[flowId].flowId[0]; 
        std::cout <<  " - Sim Time: "  <<  featuresMap[flowId].simTime[0];
        std::cout <<  " - Source IP: " <<   featuresMap[flowId].srcAddr[0]; 
        std::cout <<  " - Destination IP: "  <<  featuresMap[flowId].dstAddr[0];
        std::cout <<  " - Source Port: "  <<  featuresMap[flowId].srcPort[0]; 
        std::cout <<  " - Destination Port: "  <<  featuresMap[flowId].dstPort[0];
        std::cout <<  " - Protocol: " <<  static_cast<uint32_t>(featuresMap[flowId].proto[0]);
        std::cout <<  " - timeFirstTxPacket: " <<  featuresMap[flowId].timeFirstTxPacket[0];
        std::cout <<  " - timeLastTxPacket: " <<  featuresMap[flowId].timeLastTxPacket[0];
        std::cout <<  " - timeFirstRxPacket: " <<  featuresMap[flowId].timeFirstRxPacket[0];
        std::cout <<  " - timeLastRxPacket: "  <<  featuresMap[flowId].timeLastRxPacket[0];
        std::cout <<  " - Tx bytes: "  <<  featuresMap[flowId].txBytes[0]; 
        std::cout <<  " - Rx bytes: " <<  featuresMap[flowId].rxBytes[0]; 
        std::cout <<  " - Tx Packets: " <<  featuresMap[flowId].txPackets[0]; 
        std::cout <<  " - Rx Packets: "  <<  featuresMap[flowId].rxPackets[0]; 
        std::cout <<  " - Forwarded Packets: " <<  featuresMap[flowId].forwardedPackets[0]; 
        std::cout <<  " - Dropped Packets: " <<  featuresMap[flowId].droppedPackets[0]; 
        std::cout <<  " - Delay: "  <<  featuresMap[flowId].delaySum[0]; 
        std::cout <<  " - Jitter: " <<  featuresMap[flowId].jitterSum[0];
        std::cout <<  " - LastDelay: "  <<  featuresMap[flowId].lastDelay[0];
        */
        m_nodeId = nodeId;
        m_flowId = flowId;
        m_simTime = featuresMap[flowId].simTime[0];                            // 1 - Simulation time (elapsed seconds)
        m_srcAddr = featuresMap[flowId].srcAddr[0];
        m_dstAddr = featuresMap[flowId].dstAddr[0];                            // 3 - Destination IPv4 address
        m_srcPort = featuresMap[flowId].srcPort[0];                            // 4 - Source port
        m_dstPort = featuresMap[flowId].dstPort[0];                            // 5 - Destination port
        m_proto = featuresMap[flowId].proto[0];                                // 6 - Protocol
        m_timeFirstTxPacket = featuresMap[flowId].timeFirstTxPacket[0];
        m_timeLastTxPacket = featuresMap[flowId].timeLastTxPacket[0];
        m_timeFirstRxPacket = featuresMap[flowId].timeFirstRxPacket[0];
        m_timeLastRxPacket = featuresMap[flowId].timeLastRxPacket[0];
        m_txBytes = featuresMap[flowId].txBytes[0];                            // 10 - Sent bytes
        m_rxBytes = featuresMap[flowId].rxBytes[0];                            // 11 - Received bytes
        m_txPkts = featuresMap[flowId].txPackets[0];                              // 8 - Sent packets
        m_rxPkts = featuresMap[flowId].rxPackets[0];                              // 9 - Received packets
        m_forwardedPackets = featuresMap[flowId].forwardedPackets[0];
        m_droppedPackets = featuresMap[flowId].droppedPackets[0];
        m_delaySum = featuresMap[flowId].delaySum[0];
        m_jitterSum = featuresMap[flowId].jitterSum[0];
        m_lastDelay = featuresMap[flowId].lastDelay[0];
    }
    else {
        /*
        std::cout << std::endl << "nodeId: " << nodeId << " - FlowId: " << featuresMap[nodeId].flowId[flowIndex]; 
        std::cout <<  " - Sim Time: "  <<  featuresMap[nodeId].simTime[flowIndex];
        std::cout <<  " - Source IP: " <<   featuresMap[nodeId].srcAddr[flowIndex]; 
        std::cout <<  " - Destination IP: "  <<  featuresMap[nodeId].dstAddr[flowIndex];
        std::cout <<  " - Source Port: "  <<  featuresMap[nodeId].srcPort[flowIndex]; 
        std::cout <<  " - Destination Port: "  <<  featuresMap[nodeId].dstPort[flowIndex];
        std::cout <<  " - Protocol: " <<  static_cast<uint32_t>(featuresMap[nodeId].proto[flowIndex]);
        std::cout <<  " - timeFirstTxPacket: " <<  featuresMap[nodeId].timeFirstTxPacket[flowIndex];
        std::cout <<  " - timeLastTxPacket: " <<  featuresMap[nodeId].timeLastTxPacket[flowIndex];
        std::cout <<  " - timeFirstRxPacket: " <<  featuresMap[nodeId].timeFirstRxPacket[flowIndex];
        std::cout <<  " - timeLastRxPacket: "  <<  featuresMap[nodeId].timeLastRxPacket[flowIndex];
        std::cout <<  " - Tx bytes: "  <<  featuresMap[nodeId].txBytes[flowIndex]; 
        std::cout <<  " - Rx bytes: " <<  featuresMap[nodeId].rxBytes[flowIndex]; 
        std::cout <<  " - Tx Packets: " <<  featuresMap[nodeId].txPackets[flowIndex]; 
        std::cout <<  " - Rx Packets: "  <<  featuresMap[nodeId].rxPackets[flowIndex]; 
        std::cout <<  " - Forwarded Packets: " <<  featuresMap[nodeId].forwardedPackets[flowIndex]; 
        std::cout <<  " - Dropped Packets: " <<  featuresMap[nodeId].droppedPackets[flowIndex]; 
        std::cout <<  " - Delay: "  <<  featuresMap[nodeId].delaySum[flowIndex]; 
        std::cout <<  " - Jitter: " <<  featuresMap[nodeId].jitterSum[flowIndex];
        std::cout <<  " - LastDelay: "  <<  featuresMap[nodeId].lastDelay[flowIndex];
        */
        m_nodeId = nodeId;
        m_flowId = featuresMap[nodeId].flowId[flowIndex];
        m_simTime = featuresMap[nodeId].simTime[flowIndex];                            // 1 - Simulation time (elapsed seconds)
        m_srcAddr = featuresMap[nodeId].srcAddr[flowIndex];
        m_dstAddr = featuresMap[nodeId].dstAddr[flowIndex];                            // 3 - Destination IPv4 address
        m_srcPort = featuresMap[nodeId].srcPort[flowIndex];                            // 4 - Source port
        m_dstPort = featuresMap[nodeId].dstPort[flowIndex];                            // 5 - Destination port
        m_proto = featuresMap[nodeId].proto[flowIndex];                                // 6 - Protocol
        m_timeFirstTxPacket = featuresMap[nodeId].timeFirstTxPacket[flowIndex];
        m_timeLastTxPacket = featuresMap[nodeId].timeLastTxPacket[flowIndex];
        m_timeFirstRxPacket = featuresMap[nodeId].timeFirstRxPacket[flowIndex];
        m_timeLastRxPacket = featuresMap[nodeId].timeLastRxPacket[flowIndex];
        m_txBytes = featuresMap[nodeId].txBytes[flowIndex];                            // 10 - Sent bytes
        m_rxBytes = featuresMap[nodeId].rxBytes[flowIndex];                            // 11 - Received bytes
        m_txPkts = featuresMap[nodeId].txPackets[flowIndex];                              // 8 - Sent packets
        m_rxPkts = featuresMap[nodeId].rxPackets[flowIndex];                              // 9 - Received packets
        m_forwardedPackets = featuresMap[nodeId].forwardedPackets[flowIndex];
        m_droppedPackets = featuresMap[nodeId].droppedPackets[flowIndex];
        m_delaySum = featuresMap[nodeId].delaySum[flowIndex];
        m_jitterSum = featuresMap[nodeId].jitterSum[flowIndex];
        m_lastDelay = featuresMap[nodeId].lastDelay[flowIndex];
    }

    // Generate advanced features
    //std::cout << "Generate advanced features" << std::endl;
    m_flowDuration = m_timeLastRxPacket - m_timeFirstTxPacket;          // Flow duration (Last Tx - First Rx)
    //std::cout <<  " - FlowDuration: "  <<  m_flowDuration;
    if (m_flowDuration > 0) {
        m_throughput = ((m_rxBytes * 8.0) / m_flowDuration) / 1024 / 1024;;            // Throughput (Mbps)
        //std::cout <<  " - Throughput: "  <<  m_throughput;
    }
    
    if (m_txPkts > 0) {
        m_pdr = m_rxPkts / m_txPkts;
        m_plr = m_droppedPackets / m_txPkts;
        m_averageTxPacketSize = m_txBytes / m_txPkts;
        //std::cout <<  " - PDR: "  <<  m_pdr;
        //std::cout <<  " - PLR: "  <<  m_plr;
        //std::cout <<  " - AvgTxPacketSize: "  <<  m_averageTxPacketSize;
    }
    if (m_rxPkts > 0) {
        m_averageRxPacketSize = m_rxBytes / m_rxPkts;
        //std::cout <<  " - AvgRxPacketSize: "  <<  m_averageRxPacketSize;
    }
    //std::cout <<  std::endl;
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