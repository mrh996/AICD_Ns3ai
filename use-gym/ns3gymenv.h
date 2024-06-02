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


#ifndef NS3_GYM_ENV_H
#define NS3_GYM_ENV_H

#include <ns3/ai-module.h>

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
    //rxPackets: The number of packets received by the node.
    //txPackets: The number of packets transmitted by the node.
    //avgPacketSize: The average size of the packets transmitted, calculated as the total transmitted bytes divided by the number of transmitted packets.
    void SetStats(uint32_t rxPackets, uint32_t txPackets, double avgPacketSize, uint32_t nodeConnections);

private:
    // Variable(s) to receive the action(s) from the Gym Env
    uint32_t m_rxAction;
    bool m_attackSuccess;
    float m_cumulativeReward; // New variable to track cumulative reward
// Variable(s) to store the flow stats
    uint32_t m_rxPackets; // The number of packets received by the node.
    uint32_t m_txPackets; // txPackets: The number of packets transmitted by the node.
    double m_avgPacketSize; // avgPacketSize: The average size of the packets transmitted, calculated as the total transmitted bytes divided by the number of transmitted packets.
    uint32_t m_nodeConnections; // current node connections the action(s) from the Gym Env
    uint32_t m_rxAction;

};

} // namespace ns3

#endif // NS3_GYM_ENV_H
