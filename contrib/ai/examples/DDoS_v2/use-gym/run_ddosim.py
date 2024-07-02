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
# Modify: Ronghui Mu <ronghui.mu@liverpool.ac.uk>

import ns3ai_gym_env
import gymnasium as gym
import sys
import traceback
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.vec_env import DummyVecEnv

# Definition of an agent in the Gym env
class GymAgent:

    def __init__(self):
        pass

    def get_action(self, obs, reward, done, info):
        act = env.action_space.sample()
        return act

# Setting up the Gym env
env = gym.make("ns3ai_gym_env/Ns3-v0", targetName="ns3ai_ddos_gym", ns3Path="../../../../../")

# Check if the environment is valid
check_env(env)

# Wrap the environment with DummyVecEnv for vectorized environment support
env = DummyVecEnv([lambda: env])

try:
    # Define the PPO model with reduced training parameters
    model = PPO("MlpPolicy", env, verbose=1, learning_rate=0.001, n_steps=5, batch_size=2, n_epochs=5, gamma=0.99, gae_lambda=0.95, clip_range=0.2, ent_coef=0.0, vf_coef=0.5, max_grad_norm=0.5, tensorboard_log=None)

    # Train the model for a smaller number of timesteps
    model.learn(total_timesteps=1000)

    # Save the trained model
    model.save("ppo_ddos")

    # Test the trained model
    obs = env.reset()
    for i in range(10):
        action, _states = model.predict(obs, deterministic=True)
        obs, reward, done, info = env.step(action)
        print(f"Testing Step: {i}, Action: {action}, Reward: {reward}, Done: {done}")
        if done:
            obs = env.reset()

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
    # Close the environment
    env.close()
