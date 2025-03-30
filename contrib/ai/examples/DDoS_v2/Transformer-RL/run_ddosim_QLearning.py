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
import os
import ns3ai_gym_env
import gymnasium as gym
import numpy as np
import random
import time
import argparse
import sys
import traceback
import time
import psutil
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.vec_env import DummyVecEnv
from dataclasses import dataclass, field
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque



# python run_ddosim_QLearning.py > /LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/QL_result/test.log
# cd ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/use-gym/

env = gym.make("ns3ai_gym_env/Ns3-v0", targetName="ns3ai_ddos_gym", ns3Path="../../../../../")


ob_space = env.observation_space  
ac_space = env.action_space      
state_dim = ob_space.shape[0]     
action_dim = ac_space.n          

print(f"State space: {ob_space}, Action space: {ac_space}")

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Using device:", device)

class DQN(nn.Module):
    def __init__(self, state_dim, action_dim):
        super(DQN, self).__init__()

        self.fc1 = nn.Linear(state_dim, 256)
        self.fc2 = nn.Linear(256, 256)
        self.fc3 = nn.Linear(256, 256)
        
        self.lstm = nn.LSTM(input_size=256, hidden_size=256, batch_first=True)

        self.fc_out = nn.Linear(256, action_dim)

        self.layer_norm = nn.LayerNorm(256)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        x = torch.relu(self.fc3(x))
        
        # LSTM 
        x, _ = self.lstm(x.unsqueeze(0))  # batch_size=1
        x = x.squeeze(0)

        x = self.layer_norm(x)

        return self.fc_out(x)  

# init DQN
dqn = DQN(state_dim, action_dim).to(device)
target_dqn = DQN(state_dim, action_dim).to(device)
target_dqn.load_state_dict(dqn.state_dict())  
target_dqn.eval()

# training parameters
gamma = 0.9  
epsilon = 1.0  
min_epsilon = 0.1  
batch_size = 16
episodes = 200  
max_steps_per_episode = 70  
memory = deque(maxlen=20000)  
optimizer = optim.Adam(dqn.parameters(), lr=0.003)
loss_fn = nn.MSELoss()

# checkpoint directory
checkpoint_dir = "/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/checkpoints_dqn_v2/0317"
if not os.path.exists(checkpoint_dir):
    os.makedirs(checkpoint_dir)

best_reward = float('-inf') 

# training loop
for episode in range(episodes):
    print(f"Current Episode {episode}", flush=True)
    state = env.reset()[0]
    state = torch.tensor(state, dtype=torch.float32, device=device)
    total_reward = 0
    done = False
    steps = 0
    
    while not done and steps < max_steps_per_episode:
        if random.uniform(0, 1) < epsilon:
            action = env.action_space.sample()  
        else:
            with torch.no_grad():
                q_values = dqn(state.unsqueeze(0))  
                action = torch.argmax(q_values).item() 
                
        next_state, reward, done, _, _ = env.step(action)
        total_reward += reward
        next_state = torch.tensor(next_state, dtype=torch.float32, device=device)

        # save to memory
        memory.append((state.cpu().numpy(), action, reward, next_state.cpu().numpy(), done))
        state = next_state
        steps += 1

        # train the DQN
        if len(memory) > batch_size:   
            batch = random.sample(memory, batch_size)
            states, actions, rewards, next_states, dones = zip(*batch)
            states = torch.tensor(np.array(states), dtype=torch.float32, device=device)
            actions = torch.tensor(actions, dtype=torch.int64, device=device)
            rewards = torch.tensor(rewards, dtype=torch.float32, device=device)
            next_states = torch.tensor(np.array(next_states), dtype=torch.float32, device=device)
            dones = torch.tensor(dones, dtype=torch.bool, device=device) 
            
            q_values = dqn(states).gather(1, actions.unsqueeze(1)).squeeze()

            # calculate target Q values
            next_q_values = target_dqn(next_states).gather(1, dqn(next_states).argmax(1, keepdim=True)).squeeze().detach()
            next_q_values[dones] = 0  # Q value of terminal states is 0

            # calculate target
            target_q_values = rewards + gamma * next_q_values

            # calculate loss
            loss = loss_fn(q_values, target_q_values)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    # update target network
    if episode % 2 == 0:
        target_dqn.load_state_dict(dqn.state_dict())

    # save checkpoint
    checkpoint_path = os.path.join(checkpoint_dir, f"dqn_ns3_ddos_episode_{episode}.pth")
    torch.save({
        'episode': episode,
        'model_state_dict': dqn.state_dict(),
        'optimizer_state_dict': optimizer.state_dict(),
        'total_reward': total_reward,
        'epsilon': epsilon,
        'steps': steps
    }, checkpoint_path)
    
    # save best model
    if total_reward > best_reward:
        best_reward = total_reward
        best_model_path = os.path.join(checkpoint_dir, "dqn_ns3_ddos_best.pth")
        torch.save({
            'episode': episode,
            'model_state_dict': dqn.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'total_reward': total_reward,
            'epsilon': epsilon,
            'steps': steps,
            'best_reward': best_reward
        }, best_model_path)
    
    # decay epsilon
    epsilon = max(min_epsilon, 1.0 - episode / episodes)

    print(f"Episode {episode}, Total Reward: {total_reward}, Epsilon: {epsilon:.4f}, Steps: {steps}", flush=True)

print("Training successfully!")

# save final model
final_model_path = os.path.join(checkpoint_dir, "dqn_ns3_ddos_final.pth")
torch.save({
    'model_state_dict': dqn.state_dict(),
    'optimizer_state_dict': optimizer.state_dict(),
    'total_episodes': episodes,
    'final_epsilon': epsilon,
    'final_reward': total_reward
}, final_model_path)

print("Final DQN Saved!", flush=True)

# ===================== Testing Start =====================
print("\n开始测试模型性能...", flush=True)


test_episodes = 100  
test_results = []
test_actions_distribution = [0, 0, 0, 0]  
temperature = 0.5 

# use the best model
# best_model = DQN(state_dim, action_dim).to(device)
# checkpoint = torch.load("/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/checkpoints_dqn_v2_0317/dqn_ns3_ddos_best.pth", map_location=device)
# best_model.load_state_dict(checkpoint["model_state_dict"])
best_model = target_dqn 
best_model.eval()  


# create a result file
result_file_path = os.path.join(checkpoint_dir, "test_results_0317.txt")
with open(result_file_path, 'w') as result_file:
    result_file.write("========== DQN Testing Result ==========\n\n")
    
    # test the model
    for episode in range(test_episodes):
        state = env.reset()[0]
        state = torch.tensor(state, dtype=torch.float32, device=device)
        episode_reward = 0
        episode_steps = 0
        done = False
        episode_actions = []
        
        while not done and episode_steps < max_steps_per_episode:
            with torch.no_grad():
                q_values = best_model(state.unsqueeze(0))
                
                if random.uniform(0, 1) < epsilon:
                    action = env.action_space.sample()  
                else:
                    with torch.no_grad():
                        q_values = dqn(state.unsqueeze(0))  
                        action = torch.argmax(q_values).item() 
            
            next_state, reward, done, _, _ = env.step(action)
            episode_reward += reward
            episode_steps += 1
            state = torch.tensor(next_state, dtype=torch.float32, device=device)
        
        test_results.append({
            "episode": episode,
            "reward": episode_reward,
            "steps": episode_steps,
            "actions": episode_actions
        })
        
        # write the result to the file
        result_str = f"Test Episode {episode+1}/{test_episodes}, Reward: {episode_reward:.2f}, Steps: {episode_steps}\n"
        result_file.write(result_str)
        print(result_str, end="", flush=True)

    # average reward and steps
    avg_reward = sum(result["reward"] for result in test_results) / test_episodes
    avg_steps = sum(result["steps"] for result in test_results) / test_episodes
    total_actions = sum(test_actions_distribution)
    action_distribution_percent = [count/total_actions*100 for count in test_actions_distribution]

    # write the summary to the file
    summary = "\n========== Summary of test results ==========\n"
    summary += f"Avg reward: {avg_reward:.2f}\n"
    summary += f"Avg Step: {avg_steps:.2f}\n"
    summary += f"Action distribution: [0: {action_distribution_percent[0]:.1f}%, 1: {action_distribution_percent[1]:.1f}%, " + \
              f"2: {action_distribution_percent[2]:.1f}%, 3: {action_distribution_percent[3]:.1f}%]\n"
    
    result_file.write(summary)
    print(summary, flush=True)

print(f"Test results saved in {result_file_path}", flush=True)
print("Resting Done！", flush=True)




