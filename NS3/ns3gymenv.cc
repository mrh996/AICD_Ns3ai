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
    uint32_t parameterNum = 1;
    float low = 0.0;
    float high = 10000.0;
    std::vector<uint32_t> shape = {
        parameterNum,
    };
    std::string dtype = TypeNameGet<uint32_t>();

    Ptr<OpenGymBoxSpace> box = CreateObject<OpenGymBoxSpace>(low, high, shape, dtype);
    NS_LOG_INFO("Ns3GetActionSpace: " << box);
    return box;
}

/*
Callback to define observation space
*/
Ptr<OpenGymSpace>
Ns3GymEnv::GetObservationSpace()
{
    // m_rxPackets
    uint32_t parameterNum = 1;
    float low = 0.0;
    float high = 10000.0;
    std::vector<uint32_t> shape = {
        parameterNum,
    };
    std::string dtype = TypeNameGet<uint64_t>();

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
    // Setting this to false will let the simulation run until it finishes
    // A condition can be implemented to terminate the NS3 simulation from the Gym env by setting this to true
    bool isGameOver = false;
    NS_LOG_UNCOND ("Ns3GetGameOver: " << isGameOver);
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
    uint32_t parameterNum = 1;
    std::vector<uint32_t> shape = {
        parameterNum,
    };
    Ptr<OpenGymBoxContainer<uint64_t>> box = CreateObject<OpenGymBoxContainer<uint64_t>>(shape);

    box->AddValue(m_rxPackets);

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
    float reward = 1.0;

    if (m_rxPackets == 0)
        reward = 0.0;
    else
        reward = 1.0;

    NS_LOG_UNCOND ("Ns3GetReward: " << reward);
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
    Ptr<OpenGymBoxContainer<uint32_t>> box = DynamicCast<OpenGymBoxContainer<uint32_t>>(action);
    m_rxAction = box->GetValue(0);

    NS_LOG_INFO("Ns3ExecuteActions: " << action);
    return true;
}

// Setter and getter functions to exhange data with the Gym env

/*
Generate flow stats
*/
void
Ns3GymEnv::SetStats(uint32_t rxPackets)
{
    m_rxPackets = rxPackets;
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