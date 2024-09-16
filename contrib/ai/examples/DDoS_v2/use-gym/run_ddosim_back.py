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
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.vec_env import DummyVecEnv
#import argparse
#import sys
#import traceback
#import time

"""
def uint32_to_ipv4_address(address):
    # Extract each byte from the address
    byte1 = (address >> 24) & 0xFF
    byte2 = (address >> 16) & 0xFF
    byte3 = (address >> 8) & 0xFF
    byte4 = address & 0xFF
    
    # Format as a dotted-decimal string
    return f"{byte1}.{byte2}.{byte3}.{byte4}"
"""

# Definition of an agent in the Gym env
class GymAgent:

    def __init__(self):
        pass

    def get_action(self, obs, reward, done, info):
        # env.action_space.sample() return a random action from the action space
        act = env.action_space.sample()
        return act
    
    """
    # Perform action(s) by retrieving the observations from NS3
    def get_action(self, obs, reward, done, info):
        # obs contains the observation(s) from NS3
        # obs[0] contains the value of m_rxPackets in NS3
        simTime = obs[0];            # Simulation time (elapsed seconds)
        srcAddr = obs[1];            # Source IPv4 address
        dstAddr = obs[2];            # Destination IPv4 address
        flowDuration = obs[3];       # Flow duration (Last Tx - First Rx)
        txPkts = obs[4];             # Sent packets
        rxPkts = obs[5];             # Received packets
        lostPkts = obs[6];           # Lost packets
        totalTxPkts = obs[7];        # Total sent packets
        totalRxPkts = obs[8];        # Total received packets
        totalThroughput = obs[9];    # Throughput (Mbps)
        totalDelay = obs[10];        # Total delay (s)
        totalJitter = obs[11];       # Total jitter (s)
        totalLostPkts = obs[12];     # Total packets lost
        pdr = obs[13];               # Packet Delivery Ratio
        plr = obs[14];               # Packet Loss Ratio
        averageThroughput = obs[15]; # Average Throughput (Mbps)
        averageDelay = obs[16];      # Average End to End delay (s)
        averageJitter = obs[17];     # Average jitter Jitter (s)


        print("Observation retrieved by agent: ")
        print("Flow ", uint32_to_ipv4_address(srcAddr), ",", uint32_to_ipv4_address(dstAddr) , "rxPackets", rxPkts)
        start_time = time.time()
        time.sleep(20)
        elapsed_time = time.time() - start_time
        print("waited for 20 s : ", elapsed_time)
        act = rxPkts

        return [act]
    """

# Setting up the Gym env
env = gym.make("ns3ai_gym_env/Ns3-v0", targetName="ns3ai_ddos_gym", ns3Path="../../../../../")

# Check if the environment is valid
check_env(env)

# Wrap the environment with DummyVecEnv for vectorized environment support
env = DummyVecEnv([lambda: env])

# Define the PPO model with reduced training parameters
model = PPO("MlpPolicy", env, verbose=1, learning_rate=0.001, n_steps=5, batch_size=5, n_epochs=5, gamma=0.99, gae_lambda=0.95, clip_range=0.2, ent_coef=0.0, vf_coef=0.5, max_grad_norm=0.5, tensorboard_log=None)

# Train the model for a smaller number of timesteps
model.learn(total_timesteps=1000)

# Save the trained model
model.save("ppo_ddos")

# Test the trained model
obs = env.reset()

#for i in range(10):
i = 0
while True:
    action, _states = model.predict(obs, deterministic=True)
    obs, reward, done, info = env.step(action)
    print(f"Testing Step: {i}, Action: {action}, Reward: {reward}, Done: {done}")
    i += 1
    if done:
        obs = env.reset()
        

# Close the environment
env.close()

"""
ob_space = env.observation_space
ac_space = env.action_space
print("Observation space: ", ob_space, ob_space.dtype)
print("Action space: ", ac_space, ac_space.dtype)

stepIdx = 0

try:
    # Test the trained model
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
"""