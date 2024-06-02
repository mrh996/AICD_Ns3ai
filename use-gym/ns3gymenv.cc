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
    m_rxPackets = 0;
    m_rxAction = 0;
    m_attackSuccess = false;
    m_cumulativeReward = 0.0; // Initialize cumulative reward
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
    uint32_t parameterNum = 4; // Update the number of parameters
    float low = 0.0;
    float high = 10000.0;
    std::vector<uint32_t> shape = {
        parameterNum,
    };
    std::string dtype = TypeNameGet<float>();

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
    NS_LOG_FUNCTION(this);
    uint32_t parameterNum = 4; // Update the number of parameters
    std::vector<uint32_t> shape = { parameterNum };
    Ptr<OpenGymBoxContainer<float>> box = CreateObject<OpenGymBoxContainer<float>>(shape);

    box->AddValue(static_cast<float>(m_rxPackets));
    box->AddValue(static_cast<float>(m_txPackets));
    box->AddValue(static_cast<float>(m_avgPacketSize));
    box->AddValue(static_cast<float>(m_nodeConnections)); // Add the new observation

    NS_LOG_UNCOND("Ns3GetObservation: " << box);
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

// Setter and getter functions to exchange data with the Gym env

/*
Generate flow stats
*/
void
Ns3GymEnv::SetStats(uint32_t rxPackets, uint32_t txPackets, double avgPacketSize, uint32_t nodeConnections)
{
    m_rxPackets = rxPackets;
    m_txPackets = txPackets;
    m_avgPacketSize = avgPacketSize;
    m_nodeConnections = nodeConnections; // Set the new observation
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
