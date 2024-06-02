#!/usr/bin/env python3

# Copyright (c) 2023 Huazhong University of Science and Technology
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation;
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Author: Muyuan Shen <muyuan_shen@hust.edu.cn>
# Modify: Valerio Selis <v.selis@liverpool.ac.uk>

import ns3ai_gym_env
import gymnasium as gym
import argparse
import sys
import traceback

# Definition of an agent in the Gym env
class GymAgent:

    def __init__(self):
        pass

    # Perform action(s) by retrieving the observations from NS3
    def get_action(self, obs, reward, done, info):
        # obs contains the observation(s) from NS3
        # obs[0] contains the value of m_rxPackets in NS3
        rxPackets = obs[0]
        act = rxPackets + rxPackets

        return [act]

# Setting up the Gym env
env = gym.make("ns3ai_gym_env/Ns3-v0", targetName="ns3ai_ddos_gym", ns3Path="../../../../../")
ob_space = env.observation_space
ac_space = env.action_space
print("Observation space: ", ob_space, ob_space.dtype)
print("Action space: ", ac_space, ac_space.dtype)

stepIdx = 0

try:
    # Resets the environment to an initial internal state, returning an initial observation and info.
    obs, info = env.reset()

    print("Step: ", stepIdx)
    print("---obs: ", obs)
    print("---info: ", info)

    # Initialise the reward and done variables
    reward = 0
    done = False

    # Initialise the agent in the Gym env
    agent = GymAgent()

    # Loop until the NS3 simulation ends, except if GetGameOver in NS3 returns true
    while True:
        stepIdx += 1
        action = agent.get_action(obs, reward, done, info)
        print("---action: ", action)
        # Run one timestep of the environment's dynamics using the agent actions.
        obs, reward, done, _, info = env.step(action)

        print("Step: ", stepIdx)
        print("---obs, reward, done, info: ", obs, reward, done, info)

        if done:
            break

except Exception as e:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print("Exception occurred: {}".format(e))
    print("Traceback:")
    traceback.print_tb(exc_traceback)
    sys.exit(1)

else:
    pass

finally:
    print("Finally exiting...")
    env.close()