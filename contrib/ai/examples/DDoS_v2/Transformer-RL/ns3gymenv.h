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
 * Modify: Jinwei Hu <jinwei.hu@liverpool.ac.uk> *
 */


#ifndef NS3_GYM_ENV_H
#define NS3_GYM_ENV_H

#include <ns3/ai-module.h>
#include "ns3/ipv4-address.h"
#include "structures.h"

namespace ns3 {

class Ns3GymEnv : public OpenGymEnv
{
public:
    Ns3GymEnv ();
    ~Ns3GymEnv() override;
    static TypeId GetTypeId (void);
    void DoDispose() override;
    Ptr<OpenGymSpace> GetActionSpace() override;
    bool GetGameOver() override;
    float GetReward() override;
    std::string GetExtraInfo() override;

    Ptr<OpenGymSpace> GetObservationSpace() override;
    Ptr<OpenGymDataContainer> GetObservation() override;

    bool ExecuteActions(Ptr<OpenGymDataContainer> action) override;

    // Notify for new stats and retrieve action(s) from the Gym Env (Python)
    uint32_t NotifyGetAction();
    // Send flow stats to the Gym Env (Python)
    void SetStats(AggregateFeatures& agg, bool isSuspiciousListEmpty, bool testSuspiciousSuccess, bool promoteBlackSuccess);
    // void SetStats(int nodeId, int flowId, int flowIndex, FeaturesMap& nodeIdFeaturesMap, bool isBlack);
    // get white list
    std::set<int>& GetWhitelist();

private:
    double m_nodeId;
    uint32_t m_flowId;
    double m_simTime;               // Simulation time (elapsed seconds)
    uint32_t m_srcAddr;             // Source IPv4 address
    uint32_t m_dstAddr;             // Destination IPv4 address
    uint16_t m_srcPort;             // Source port
    uint16_t m_dstPort;             // Destination port
    uint8_t m_proto;                // Protocol
    double m_timeFirstTxPacket;
    double m_timeLastTxPacket;
    double m_timeFirstRxPacket;
    double m_timeLastRxPacket;
    double m_txBytes;               // Sent bytes
    double m_rxBytes;               // Received bytes
    double m_txPkts;                // Sent packets
    double m_rxPkts;                // Received packets
    uint32_t m_forwardedPackets;
    uint32_t m_droppedPackets;
    double m_delaySum;
    double m_jitterSum;
    double m_lastDelay;
    double m_throughput;            // Throughput (Mbps)
    double m_flowDuration;          // Flow duration (Last Tx - First Rx)
    double m_pdr;                   // Packet Delivery Ratio
    double m_plr;                   // Packet Loss Ratio
    double m_averageTxPacketSize;   // Average transmitted packet size
    double m_averageRxPacketSize;   // Average received packet size
    
    std::set<int> m_whitelist;  // white list 

    uint32_t flowCount;        // the number of flowCount
    double m_lastRewardTime;      // Time when last reward was calculated
    double m_timeWindow;         // Time window for calculating long-term reward

    // Initialize network performance variables
    double m_sumPdr;
    double m_sumDelay;
    double m_sumPlr;
    double m_observationCount;

    // Variable(s) to receive the action(s) from the Gym Env
    uint32_t m_rxAction;
    uint32_t m_defendtype;
    bool m_attackSuccess;
    bool m_defendSuccess; 
    float m_cumulativeReward;       // New variable to track cumulative reward

    // Aggregate statistics variables
    uint32_t m_aggFlowCount;        // Number of active flows
    uint32_t m_aggTxBytesInc;         // Total transmitted bytes increment
    uint32_t m_aggRxBytesInc;         // Total received bytes increment
    uint32_t m_aggTxPacketsInc;       // Total transmitted packets increment
    uint32_t m_aggRxPacketsInc;       // Total received packets increment
    uint32_t m_aggDroppedInc;       // Total dropped packets increment
    double m_aggDelayInc;           // Average delay increment
    double m_aggJitterInc;          // Average jitter increment
    double m_aggThroughput;         // Aggregate throughput (Mbps)
    double m_aggPdr;                // Aggregate packet delivery ratio
    double m_aggPlr;                // Aggregate packet loss ratio
    double m_lastplr;
    bool m_isSuspiciousListEmpty;
    bool m_testSuspiciousSuccess;
    bool m_promoteBlackSuccess;
    uint32_t m_observe_time;
    uint32_t m_timeStep;
    uint32_t m_totalActions;
    uint32_t m_successfulDefenses;
    uint32_t m_NoRemove_time;
};

} // namespace ns3

#endif // NS3_GYM_ENV_H
