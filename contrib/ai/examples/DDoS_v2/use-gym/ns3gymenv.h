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


#ifndef NS3_GYM_ENV_H
#define NS3_GYM_ENV_H

#include <ns3/ai-module.h>
#include "ns3/ipv4-address.h"

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
    void SetStats(std::string flowId, double simTime, uint32_t srcAddr, uint32_t dstAddr, uint16_t srcPort,
                  uint16_t dstPort, uint8_t proto, double flowDuration, double txPkts, double rxPkts,
                  double txBytes, double rxBytes, double lostPkts, double throughput,
                  std::unordered_map<std::string, std::vector<double>> flowsDict,
                  double totalTxPkts, double totalRxPkts, double totalThroughput, double totalDelay,
                  double totalJitter, double totalLostPkts, double pdr, double plr,
                  double averageTxPacketSize, double averageRxPacketSize,
                  double averageThroughput, double averageDelay, double averageJitter, uint32_t activeFlows);

private:
    std::string m_flowId;
    double m_simTime;               // Simulation time (elapsed seconds)
    uint32_t m_srcAddr;             // Source IPv4 address
    uint32_t m_dstAddr;             // Destination IPv4 address
    uint16_t m_srcPort;             // Source port
    uint16_t m_dstPort;             // Destination port
    uint8_t m_proto;                // Protocol
    double m_flowDuration;          // Flow duration (Last Tx - First Rx)
    double m_txPkts;                // Sent packets
    double m_rxPkts;                // Received packets
    double m_txBytes;               // Sent bytes
    double m_rxBytes;               // Received bytes
    double m_lostPkts;              // Lost packets
    double m_throughput;            // Throughput (Mbps)
    double m_totalTxPkts;           // Total sent packets
    double m_totalRxPkts;           // Total received packets
    double m_totalTxBytes;          // Total sent bytes
    double m_totalRxBytes;          // Total received bytes
    double m_totalFlowDuration;     // Total flow duration
    double m_totalThroughput;       // Total throughput (Mbps)
    double m_totalDelay;            // Total delay (s)
    double m_totalJitter;           // Total jitter (s)
    double m_totalLostPkts;         // Total packets lost
    double m_pdr;                   // Packet Delivery Ratio
    double m_plr;                   // Packet Loss Ratio
    double m_averageTxPacketSize;   // Average transmitted packet size
    double m_averageRxPacketSize;   // Average received packet size
    double m_averageThroughput;     // Average Throughput (Mbps)
    double m_averageDelay;          // Average End to End delay (s)
    double m_averageJitter;         // Average jitter Jitter (s)
    uint32_t m_activeFlows;         // Active nodes/flows

    // Variable(s) to receive the action(s) from the Gym Env
    uint32_t m_rxAction;
    
    bool m_attackSuccess;
    float m_cumulativeReward;       // New variable to track cumulative reward
};

} // namespace ns3

#endif // NS3_GYM_ENV_H
