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
 * 2025 University of Liverpool
 * Modify: Valerio Selis <v.selis@liverpool.ac.uk>
 * Modify: Ronghui Mu <ronghui.mu@liverpool.ac.uk>
 * Modify: Jinwei Hu <jinwei.hu@liverpool.ac.uk>
 *
 */

#include "ns3gymenv.h"
#include "ns3/ipv4-address.h"
namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("ns3_gym_env");

NS_OBJECT_ENSURE_REGISTERED (Ns3GymEnv);

/*
Convert an unsigned int into an IPv4 address
*/
void PrintIpv4Address(uint32_t addrInt)
{
    uint32_t byte1 = (addrInt >> 24) & 0xFF;
    uint32_t byte2 = (addrInt >> 16) & 0xFF;
    uint32_t byte3 = (addrInt >> 8) & 0xFF;
    uint32_t byte4 = addrInt & 0xFF;

    std::cout << byte1 << "." << byte2 << "." << byte3 << "." << byte4;
}

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
    // m_forwardedPackets = 0;
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
    
    m_lastRewardTime = 0.0;      // Time when last reward was calculated

    // Initialize network performance variables
    m_sumPdr = 0.0;
    m_sumDelay = 0.0;
    m_sumPlr = 0.0;
    m_observationCount = 0;

    m_rxAction = 0;
    m_defendtype = 0;
    m_attackSuccess = false;
    m_defendSuccess = false;
    m_cumulativeReward = 0.0;      // Initialize cumulative reward
    // Fixed whitelist containing predefined IP addresses
    m_whitelist = {167772418, 167772674, 167838212, 167838213};

    // Add aggregate statistics variables
    m_aggFlowCount = 0;          // Current number of active flows
    m_aggTxBytesInc = 0;         // Total transmitted bytes increment
    m_aggRxBytesInc = 0;         // Total received bytes increment 
    m_aggTxPacketsInc = 0;       // Total transmitted packets increment
    m_aggRxPacketsInc = 0;       // Total received packets increment
    m_aggDroppedInc = 0;         // Total dropped packets increment
    m_aggDelayInc = 0;           // Average delay increment
    m_aggJitterInc = 0;          // Average jitter increment
    m_aggThroughput = 0;         // Aggregate throughput
    m_aggPdr = 0;                // Aggregate packet delivery ratio
    m_aggPlr = 0;                // Aggregate packet loss ratio
    m_timeWindow = 0.05;         // Time window
    m_isSuspiciousListEmpty = true; // Flag indicating if suspicious list is empty
    m_testSuspiciousSuccess = false;
    m_promoteBlackSuccess = false;
    
    m_lastplr = 0.0;
    m_observe_time = 0;
    m_timeStep = 0;
    m_totalActions = 0;
    m_successfulDefenses = 0;
    m_NoRemove_time = 0;
}

std::set<int>& 
Ns3GymEnv::GetWhitelist()
{
    return m_whitelist;
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
    uint32_t n = 4; // Number of possible actions (0, 1, 2)
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
    uint32_t parameterNum = 12; // Update the number of parameters
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
    bool isGameOver = (m_cumulativeReward >= 200000);

    if (isGameOver)
    {
        // Optionally, reset m_attackSuccess and m_cumulativeReward here for the next episode
        // m_defendSuccess = 0;
        m_cumulativeReward = 0.0; // Reset cumulative reward for the next episode
    }

    NS_LOG_UNCOND("Ns3GetGameOver: " << isGameOver);
    return isGameOver;
}


Ptr<OpenGymDataContainer>
Ns3GymEnv::GetObservation()
{
    NS_LOG_FUNCTION (this);
    uint32_t parameterNum = 12;  // observation
    std::vector<uint32_t> shape = {
        parameterNum,
    };
    Ptr<OpenGymBoxContainer<double>> box = CreateObject<OpenGymBoxContainer<double>>(shape);

    std::cout << "GetObs - Aggregate Stats at Time " << m_simTime << " s" << std::endl;

    // Add aggregate statistics as observation space
    box->AddValue(m_simTime);               // 1 - Simulation time
    box->AddValue(m_aggFlowCount);          // 2 - Number of active flows
    box->AddValue(m_aggTxBytesInc);         // 3 - Total transmitted bytes increment
    box->AddValue(m_aggRxBytesInc);         // 4 - Total received bytes increment
    box->AddValue(m_aggTxPacketsInc);       // 5 - Total transmitted packets increment
    box->AddValue(m_aggRxPacketsInc);       // 6 - Total received packets increment
    box->AddValue(m_aggDroppedInc);         // 7 - Total dropped packets increment
    box->AddValue(m_aggDelayInc);           // 8 - Average delay increment
    box->AddValue(m_aggJitterInc);          // 9 - Average jitter increment
    box->AddValue(m_aggThroughput);         // 10 - Aggregate throughput
    box->AddValue(m_aggPdr);                // 11 - Aggregate packet delivery ratio
    box->AddValue(m_aggPlr);                // 12 - Aggregate packet loss ratio
    NS_LOG_UNCOND ("Ns3GetObservation (Aggregate): " << box);
    return box;
}



float Ns3GymEnv::GetReward() {
    NS_LOG_FUNCTION(this);
    float reward = 0.0;
    const uint32_t OBSERVE_THRESHOLD = 3;
    const uint32_t REMOVE_THRESHOLD = 3;
    const float BASE_REWARD = 100.0;
    
    // track rewards/penalties
    float normalStateBaseReward = 0.0;
    float attackStateBasePenalty = 0.0;
    float observePenalty = 0.0;
    float addRewardPenalty = 0.0;
    float removeRewardPenalty = 0.0;
    float noRemovePenalty = 0.0;
    float promoteRewardPenalty = 0.0;
    
    // network state
    bool isNormalState = (m_aggFlowCount > 0) ? (m_aggPlr <= 0.1) : false;
    bool isAttackState = !isNormalState;
    
    // dealing with observational behaviour
    if (m_defendtype == 0) {
        m_observe_time += 1;
        if (m_observe_time > OBSERVE_THRESHOLD) {
            observePenalty = ((m_observe_time / OBSERVE_THRESHOLD) + 1) * 2 * BASE_REWARD;
            reward -= observePenalty;
        }
    } else {
        m_observe_time = 0;
    }
    
    if (isNormalState) {
        m_successfulDefenses++;
        normalStateBaseReward = ((m_successfulDefenses / 5) + 1) * BASE_REWARD;
        reward += normalStateBaseReward;
        
        // reward/penalty for specific actions
        if (m_defendtype == 1) {
            addRewardPenalty = -3 * BASE_REWARD;
            reward += addRewardPenalty;
        } 
        
        if (m_defendtype == 2) {
            if (m_testSuspiciousSuccess) {
                removeRewardPenalty = 3 * BASE_REWARD;
                reward += removeRewardPenalty;
            }
            m_NoRemove_time = 0;
        } else {
            if (!m_isSuspiciousListEmpty && m_NoRemove_time > REMOVE_THRESHOLD) {               
                noRemovePenalty = ((m_NoRemove_time / REMOVE_THRESHOLD) + 1) * BASE_REWARD;
                reward -= noRemovePenalty;
            }
            m_NoRemove_time++; 
        }
        
        if (m_defendtype == 3 && m_promoteBlackSuccess) {
            promoteRewardPenalty = 10 * BASE_REWARD;
            reward += promoteRewardPenalty;
        }
        
        std::cout << "Current state is Normal, successful defenses: " << m_successfulDefenses << std::endl;
    } else {
        m_successfulDefenses = 0;
        
        attackStateBasePenalty = -2 * BASE_REWARD;
        reward += attackStateBasePenalty;
        
        if (m_defendtype == 1) {
            addRewardPenalty = 3 * BASE_REWARD;
            reward += addRewardPenalty;
        } else {
            addRewardPenalty = -5 * BASE_REWARD;
            reward += addRewardPenalty;
        }
        
        std::cout << "Current state is Under Attack, PLR: " << m_aggPlr << " PDR: " << m_aggPdr << std::endl; 
    }
    

    
    // update state
    m_cumulativeReward += reward;
    m_timeStep++;
    
    // log output
    std::cout << "GetReward: " << reward 
                << ", CumulativeReward: " << m_cumulativeReward 
                << ", ObserveTime: " << m_observe_time 
                << ", NoRemoveTime: " << m_NoRemove_time 
                << ", PLR: " << m_aggPlr
                << ", PDR: " << m_aggPdr
                << ", TimeStep: " << m_timeStep << std::endl;
    
    std::cout << "Reward Breakdown: ";
    if (isNormalState) {
        std::cout << "Normal state base: " << normalStateBaseReward;
    } else {
        std::cout << "Attack state base: " << attackStateBasePenalty;
    }
    
    if (observePenalty != 0) {
        std::cout << ", Observe penalty: " << -observePenalty;
    }
    
    if (addRewardPenalty != 0) {
        std::cout << ", Add action: " << addRewardPenalty;
    }
    
    if (removeRewardPenalty != 0) {
        std::cout << ", Remove action: " << removeRewardPenalty;
    }
    
    if (noRemovePenalty != 0) {
        std::cout << ", No remove penalty: " << -noRemovePenalty;
    }
    
    if (promoteRewardPenalty != 0) {
        std::cout << ", Promote action: " << promoteRewardPenalty;
    }
    
    
    std::cout << std::endl;
    
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

bool
Ns3GymEnv::ExecuteActions(Ptr<OpenGymDataContainer> action)
{
    // Get the action
    Ptr<OpenGymDiscreteContainer> discrete = DynamicCast<OpenGymDiscreteContainer>(action);
    uint32_t defendType = discrete->GetValue();
    m_rxAction = defendType;
    std::cout << "Execute action: m_rxAction: " << m_rxAction << std::endl;
    // Execute corresponding operation based on action type
    switch (m_rxAction) {
        case 0:
            // Silent observation, no defense measures taken
            m_defendtype = 0;
            std::cout << "No defense, observing network state" << std::endl;
            break;
        case 1:
            // Add address with highest suspicious score to suspicious list
            m_defendtype = 1;
            std::cout << "Push highest suspicious score address to SuspiciousList" << std::endl;
            break;
        case 2:
            // Remove address with lowest suspicious score from suspicious list
            m_defendtype = 2;
            std::cout << "Pop lowest suspicious score address from SuspiciousList" << std::endl;
            break;
        case 3:
            // Promote qualifying addresses from suspicious list to blacklist
            m_defendtype = 3;
            std::cout << "Promote addresses from SuspiciousList to Blacklist" << std::endl;
            break;
        default:
            // Invalid action, log and return
            m_defendtype = 0;
            std::cout << "Invalid action, no defense applied" << std::endl;
            break;
    }
    NS_LOG_INFO("ExecuteActions: defendType=" << defendType);
    return true;
}


/*
Set aggregated network statistics
*/
void
Ns3GymEnv::SetStats(AggregateFeatures& agg, bool isSuspiciousListEmpty, bool testSuspiciousSuccess, bool promoteBlackSuccess)
{
    m_isSuspiciousListEmpty = isSuspiciousListEmpty;
    m_testSuspiciousSuccess = testSuspiciousSuccess;
    m_promoteBlackSuccess = promoteBlackSuccess; 
    // Store aggregate statistics in member variables
    m_aggFlowCount = agg.flowCount;
    m_simTime = agg.simTime;
    m_aggTxBytesInc = agg.totalTxBytesInc;
    m_aggRxBytesInc = agg.totalRxBytesInc;
    m_aggTxPacketsInc = agg.totalTxPacketsInc;
    m_aggRxPacketsInc = agg.totalRxPacketsInc;
    m_aggDroppedInc = agg.totalDroppedInc;
    m_aggDelayInc = agg.avgDelayInc;
    m_aggJitterInc = agg.avgJitterInc;
    // Print aggregate network statistics
    std::cout << "\n===== Setting Aggregate Network Statistics =====" << std::endl;
    std::cout << "Current SuspiciousList is empty : " << m_isSuspiciousListEmpty << std::endl;
    std::cout << "Simulation Time: " << m_simTime << " seconds" << std::endl;
    std::cout << "Active Flows: " << m_aggFlowCount << std::endl;
    std::cout << "Total Tx Bytes (increment): " << m_aggTxBytesInc << " bytes" << std::endl;
    std::cout << "Total Rx Bytes (increment): " << m_aggRxBytesInc << " bytes" << std::endl;
    std::cout << "Total Tx Packets (increment): " << m_aggTxPacketsInc << " packets" << std::endl;
    std::cout << "Total Rx Packets (increment): " << m_aggRxPacketsInc << " packets" << std::endl;
    std::cout << "Total Dropped Packets (increment): " << m_aggDroppedInc << " packets" << std::endl;
    std::cout << "Average Delay (increment): " << m_aggDelayInc << " seconds" << std::endl;
    std::cout << "Average Jitter (increment): " << m_aggJitterInc << " seconds" << std::endl;
    
    // Calculate additional aggregate metrics
    if (m_aggFlowCount > 0) {
        // Calculate throughput (Mbps)
        if (m_simTime > 0) {
            m_aggThroughput = ((m_aggRxBytesInc * 8.0) / m_timeWindow) / 1024 / 1024;
        }
        
        // Calculate PDR and PLR
        if (m_aggTxPacketsInc > 0) {
            m_aggPdr = static_cast<double>(m_aggRxPacketsInc) / m_aggTxPacketsInc;
            m_aggPlr = static_cast<double>(m_aggDroppedInc) / m_aggTxPacketsInc;
        } else { // test in 0320?
            m_aggPdr = 0;
            m_aggPlr = 0;
        }
    } else {
        m_aggThroughput = 0;
        m_aggPdr = 0;
        m_aggPlr = 0;
    }
    std::cout << "Aggregate Throughput: " << m_aggThroughput << " Mbps" << std::endl;
    std::cout << "Aggregate PDR: " << m_aggPdr << std::endl;
    std::cout << "Aggregate PLR: " << m_aggPlr << std::endl;
    std::cout << "================================================\n" << std::endl;
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

