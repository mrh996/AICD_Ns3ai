import ns3ai_gym_env
import gymnasium as gym
import argparse
import sys
import traceback
import time
import psutil
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.utils import set_random_seed
from dataclasses import dataclass, field
import os
import random
import numpy as np
from utils import linear_schedule, update_args, load_policy_kwargs

PROCNAME = "/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/ns3.41-ns3ai_ddos_gym-debug"

# python run_ddosim_TiT.py > /LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/use-gym/simulation_TiT.log
# cd ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/use-gym/

@dataclass
class LogEntry:
    flow_id : list = field(default_factory=list)                # 2 - Flow ID
    sim_time : list = field(default_factory=list)               # 3 - Simulation time (elapsed seconds)
    src_addr : list = field(default_factory=list)               # 4 - Source IPv4 address
    dst_addr : list = field(default_factory=list)               # 5 - Destination IPv4 address
    src_port : list = field(default_factory=list)               # 6 - Source port
    dst_ort : list = field(default_factory=list)               # 7 - Destination port
    proto : list = field(default_factory=list)                 # 8 - Protocol
    time_first_tx_packet : list = field(default_factory=list)     # 9 - Time of the first TX packet (s)
    time_last_tx_packet : list = field(default_factory=list)      # 10 - Time of the last TX packet (s)
    time_first_rx_packet : list = field(default_factory=list)     # 11 - Time of the first RX packet (s)
    time_last_rx_packet : list = field(default_factory=list)      # 12 - Time of the last RX packet (s)
    tx_bytes : list = field(default_factory=list)               # 13 - Sent bytes
    rx_bytes : list = field(default_factory=list)               # 14 - Received bytes
    tx_pkts : list = field(default_factory=list)                # 15 - Sent packets
    rx_pkts : list = field(default_factory=list)                # 16 - Received packets
    forwarded_packets : list = field(default_factory=list)      # 17 - Number of forwarded packets
    dropped_packets : list = field(default_factory=list)        # 18 - Number of forwarded packets
    delay_sum : list = field(default_factory=list)              # 19 - Total delay (s)
    jitter_sum : list = field(default_factory=list)             # 20 - Total jitter (s)
    last_delay : list = field(default_factory=list)             # 21 - Last delay value (s)
    throughput : list = field(default_factory=list)            # 22 - Throughput (Mbps)
    flow_duration : list = field(default_factory=list)          # 23 - Flow duration (Last Tx - First Rx)
    pdr : list = field(default_factory=list)                   # 24 - Packet Delivery Ratio
    plr : list = field(default_factory=list)                   # 25 - Packet Loss Ratio
    average_tx_packet_size : list = field(default_factory=list)   # 26 - Average transmitted packet size (B)
    average_rx_packet_size : list = field(default_factory=list)   # 27 - Average received packet size (B)

# Dictionary containing all the logs for each node in the victim network
victim_nodes_logs = {}
# Dictionary containing overall flow stats
victim_flow_stats = {}

def uint32_to_ipv4_address(address):
    # Extract each byte from the address
    byte1 = (address >> 24) & 0xFF
    byte2 = (address >> 16) & 0xFF
    byte3 = (address >> 8) & 0xFF
    byte4 = address & 0xFF
    
    # Format as a dotted-decimal string
    return f"{byte1}.{byte2}.{byte3}.{byte4}"

# Extracts the logs from the observation
def update_nodes_logs(obs):
    node_id = obs[0]                 # 1 - Node ID (number if info of a node, -1 if overall info of a flow)
    # Populate the log for the node
    flow_id = obs[1]             # 2 - Flow ID
    index = -1
    # Check if the node ID exists
    if node_id != -1:
        # Check if the node id is already in the dictionary
        if node_id not in victim_nodes_logs.keys():
            victim_nodes_logs[node_id] = LogEntry()
        # Check if the flow is already in the log for the given node
        try:
            index = victim_nodes_logs[node_id].flow_id.index(flow_id)
        except:
            victim_nodes_logs[node_id].flow_id.append(flow_id)
        if index != -1:
            # There was already a log for the flow, update it
            victim_nodes_logs[node_id].sim_time[index] = obs[2]               # 3 - Simulation time (elapsed seconds)
            victim_nodes_logs[node_id].src_addr[index] = obs[3]               # 4 - Source IPv4 address
            victim_nodes_logs[node_id].dst_addr[index] = obs[4]               # 5 - Destination IPv4 address
            victim_nodes_logs[node_id].src_port[index] = obs[5]               # 6 - Source port
            victim_nodes_logs[node_id].dst_ort[index] = obs[6]               # 7 - Destination port
            victim_nodes_logs[node_id].proto[index] = obs[7]                 # 8 - Protocol
            victim_nodes_logs[node_id].time_first_tx_packet[index] = obs[8]     # 9 - Time of the first TX packet (s)
            victim_nodes_logs[node_id].time_last_tx_packet[index] = obs[9]      # 10 - Time of the last TX packet (s)
            victim_nodes_logs[node_id].time_first_rx_packet[index] = obs[10]     # 11 - Time of the first RX packet (s)
            victim_nodes_logs[node_id].time_last_rx_packet[index] = obs[11]      # 12 - Time of the last RX packet (s)
            victim_nodes_logs[node_id].tx_bytes[index] = obs[12]               # 13 - Sent bytes
            victim_nodes_logs[node_id].rx_bytes[index] = obs[13]               # 14 - Received bytes
            victim_nodes_logs[node_id].tx_pkts[index] = obs[14]                # 15 - Sent packets
            victim_nodes_logs[node_id].rx_pkts[index] = obs[15]                # 16 - Received packets
            victim_nodes_logs[node_id].forwarded_packets[index] = obs[16]      # 17 - Number of forwarded packets
            victim_nodes_logs[node_id].dropped_packets[index] = obs[17]        # 18 - Number of forwarded packets
            victim_nodes_logs[node_id].delay_sum[index] = obs[18]              # 19 - Total delay (s)
            victim_nodes_logs[node_id].jitter_sum[index] = obs[19]             # 20 - Total jitter (s)
            victim_nodes_logs[node_id].last_delay[index] = obs[20]             # 21 - Last delay value (s)
            victim_nodes_logs[node_id].throughput[index] = obs[21]            # 22 - Throughput (Mbps)
            victim_nodes_logs[node_id].flow_duration[index] = obs[22]          # 23 - Flow duration (Last Tx - First Rx)
            victim_nodes_logs[node_id].pdr[index] = obs[23]                   # 24 - Packet Delivery Ratio
            victim_nodes_logs[node_id].plr[index] = obs[24]                   # 25 - Packet Loss Ratio
            victim_nodes_logs[node_id].average_tx_packet_size[index] = obs[25]   # 26 - Average transmitted packet size (B)
            victim_nodes_logs[node_id].average_rx_packet_size[index] = obs[26]   # 27 - Average received packet size (B)
        else:
            # A log for the flow was not present, create it
            victim_nodes_logs[node_id].sim_time.append(obs[2])      # 3 - Simulation time (elapsed seconds)
            victim_nodes_logs[node_id].src_addr.append(obs[3])               # 4 - Source IPv4 address
            victim_nodes_logs[node_id].dst_addr.append(obs[4])               # 5 - Destination IPv4 address
            victim_nodes_logs[node_id].src_port.append(obs[5])               # 6 - Source port
            victim_nodes_logs[node_id].dst_ort.append(obs[6])              # 7 - Destination port
            victim_nodes_logs[node_id].proto.append(obs[7])                 # 8 - Protocol
            victim_nodes_logs[node_id].time_first_tx_packet.append(obs[8])     # 9 - Time of the first TX packet (s)
            victim_nodes_logs[node_id].time_last_tx_packet.append(obs[9])      # 10 - Time of the last TX packet (s)
            victim_nodes_logs[node_id].time_first_rx_packet.append(obs[10])     # 11 - Time of the first RX packet (s)
            victim_nodes_logs[node_id].time_last_rx_packet.append(obs[11])      # 12 - Time of the last RX packet (s)
            victim_nodes_logs[node_id].tx_bytes.append(obs[12])               # 13 - Sent bytes
            victim_nodes_logs[node_id].rx_bytes.append(obs[13])               # 14 - Received bytes
            victim_nodes_logs[node_id].tx_pkts.append(obs[14])                # 15 - Sent packets
            victim_nodes_logs[node_id].rx_pkts.append(obs[15])                # 16 - Received packets
            victim_nodes_logs[node_id].forwarded_packets.append(obs[16])      # 17 - Number of forwarded packets
            victim_nodes_logs[node_id].dropped_packets.append(obs[17])        # 18 - Number of forwarded packets
            victim_nodes_logs[node_id].delay_sum.append(obs[18])              # 19 - Total delay (s)
            victim_nodes_logs[node_id].jitter_sum.append(obs[19])             # 20 - Total jitter (s)
            victim_nodes_logs[node_id].last_delay.append(obs[20])             # 21 - Last delay value (s)
            victim_nodes_logs[node_id].throughput.append(obs[21])            # 22 - Throughput (Mbps)
            victim_nodes_logs[node_id].flow_duration.append(obs[22])          # 23 - Flow duration (Last Tx - First Rx)
            victim_nodes_logs[node_id].pdr.append(obs[23])                   # 24 - Packet Delivery Ratio
            victim_nodes_logs[node_id].plr.append(obs[24])                   # 25 - Packet Loss Ratio
            victim_nodes_logs[node_id].average_tx_packet_size.append(obs[25])   # 26 - Average transmitted packet size (B)
            victim_nodes_logs[node_id].average_rx_packet_size.append(obs[26])   # 27 - Average received packet size (B)
    else:
        # Check if the flow is already in the dictionary
        if flow_id not in victim_flow_stats.keys():
            victim_flow_stats[flow_id] = LogEntry()
        # Check if the flow is already in the overall flow stats
        try:
            index = victim_flow_stats[flow_id].flow_id.index(flow_id)
        except:
            victim_flow_stats[flow_id].flow_id.append(flow_id)
        if index != -1:
            # There were already flow stats for the flow, update them
            victim_flow_stats[flow_id].sim_time[index] = obs[2]               # 3 - Simulation time (elapsed seconds)
            victim_flow_stats[flow_id].src_addr[index] = obs[3]               # 4 - Source IPv4 address
            victim_flow_stats[flow_id].dst_addr[index] = obs[4]               # 5 - Destination IPv4 address
            victim_flow_stats[flow_id].src_port[index] = obs[5]               # 6 - Source port
            victim_flow_stats[flow_id].dst_ort[index] = obs[6]               # 7 - Destination port
            victim_flow_stats[flow_id].proto[index] = obs[7]                 # 8 - Protocol
            victim_flow_stats[flow_id].time_first_tx_packet[index] = obs[8]     # 9 - Time of the first TX packet (s)
            victim_flow_stats[flow_id].time_last_tx_packet[index] = obs[9]      # 10 - Time of the last TX packet (s)
            victim_flow_stats[flow_id].time_first_rx_packet[index] = obs[10]     # 11 - Time of the first RX packet (s)
            victim_flow_stats[flow_id].time_last_rx_packet[index] = obs[11]      # 12 - Time of the last RX packet (s)
            victim_flow_stats[flow_id].tx_bytes[index] = obs[12]               # 13 - Sent bytes
            victim_flow_stats[flow_id].rx_bytes[index] = obs[13]               # 14 - Received bytes
            victim_flow_stats[flow_id].tx_pkts[index] = obs[14]                # 15 - Sent packets
            victim_flow_stats[flow_id].rx_pkts[index] = obs[15]                # 16 - Received packets
            victim_flow_stats[flow_id].forwarded_packets[index] = obs[16]      # 17 - Number of forwarded packets
            victim_flow_stats[flow_id].dropped_packets[index] = obs[17]        # 18 - Number of forwarded packets
            victim_flow_stats[flow_id].delay_sum[index] = obs[18]              # 19 - Total delay (s)
            victim_flow_stats[flow_id].jitter_sum[index] = obs[19]             # 20 - Total jitter (s)
            victim_flow_stats[flow_id].last_delay[index] = obs[20]             # 21 - Last delay value (s)
            victim_flow_stats[flow_id].throughput[index] = obs[21]            # 22 - Throughput (Mbps)
            victim_flow_stats[flow_id].flow_duration[index] = obs[22]          # 23 - Flow duration (Last Tx - First Rx)
            victim_flow_stats[flow_id].pdr[index] = obs[23]                   # 24 - Packet Delivery Ratio
            victim_flow_stats[flow_id].plr[index] = obs[24]                   # 25 - Packet Loss Ratio
            victim_flow_stats[flow_id].average_tx_packet_size[index] = obs[25]   # 26 - Average transmitted packet size (B)
            victim_flow_stats[flow_id].average_rx_packet_size[index] = obs[26]   # 27 - Average received packet size (B)
        else:
            # Flow stats for the flow were not present, create them
            victim_flow_stats[flow_id].sim_time.append(obs[2])      # 3 - Simulation time (elapsed seconds)
            victim_flow_stats[flow_id].src_addr.append(obs[3])               # 4 - Source IPv4 address
            victim_flow_stats[flow_id].dst_addr.append(obs[4])               # 5 - Destination IPv4 address
            victim_flow_stats[flow_id].src_port.append(obs[5])               # 6 - Source port
            victim_flow_stats[flow_id].dst_ort.append(obs[6])              # 7 - Destination port
            victim_flow_stats[flow_id].proto.append(obs[7])                 # 8 - Protocol
            victim_flow_stats[flow_id].time_first_tx_packet.append(obs[8])     # 9 - Time of the first TX packet (s)
            victim_flow_stats[flow_id].time_last_tx_packet.append(obs[9])      # 10 - Time of the last TX packet (s)
            victim_flow_stats[flow_id].time_first_rx_packet.append(obs[10])     # 11 - Time of the first RX packet (s)
            victim_flow_stats[flow_id].time_last_rx_packet.append(obs[11])      # 12 - Time of the last RX packet (s)
            victim_flow_stats[flow_id].tx_bytes.append(obs[12])               # 13 - Sent bytes
            victim_flow_stats[flow_id].rx_bytes.append(obs[13])               # 14 - Received bytes
            victim_flow_stats[flow_id].tx_pkts.append(obs[14])                # 15 - Sent packets
            victim_flow_stats[flow_id].rx_pkts.append(obs[15])                # 16 - Received packets
            victim_flow_stats[flow_id].forwarded_packets.append(obs[16])      # 17 - Number of forwarded packets
            victim_flow_stats[flow_id].dropped_packets.append(obs[17])        # 18 - Number of forwarded packets
            victim_flow_stats[flow_id].delay_sum.append(obs[18])              # 19 - Total delay (s)
            victim_flow_stats[flow_id].jitter_sum.append(obs[19])             # 20 - Total jitter (s)
            victim_flow_stats[flow_id].last_delay.append(obs[20])             # 21 - Last delay value (s)
            victim_flow_stats[flow_id].throughput.append(obs[21])            # 22 - Throughput (Mbps)
            victim_flow_stats[flow_id].flow_duration.append(obs[22])          # 23 - Flow duration (Last Tx - First Rx)
            victim_flow_stats[flow_id].pdr.append(obs[23])                   # 24 - Packet Delivery Ratio
            victim_flow_stats[flow_id].plr.append(obs[24])                   # 25 - Packet Loss Ratio
            victim_flow_stats[flow_id].average_tx_packet_size.append(obs[25])   # 26 - Average transmitted packet size (B)
            victim_flow_stats[flow_id].average_rx_packet_size.append(obs[26])   # 27 - Average received packet size (B)


def make_array_agent(algo, seed, args):
    log_folder = args.log_folder
    device = args.device

    policy_type = 'MlpPolicy'
    policy_kwargs = load_policy_kwargs(args)
    env = gym.make("ns3ai_gym_env/Ns3-v0", targetName="ns3ai_ddos_gym", ns3Path="../../../../../")
    ob_space = env.observation_space
    ac_space = env.action_space
    print("Observation space: ", ob_space, ob_space.dtype)
    print("Action space: ", ac_space, ac_space.dtype)
    # Resets the environment to an initial internal state, returning an initial observation and info.
    obs, info = env.reset()
    print("---obs: ", obs)
    print("---info: ", info)
    check_env(env)
    env = DummyVecEnv([lambda: env])
    agent = PPO(policy_type, env, verbose=1, learning_rate=0.001, n_steps=5, batch_size=5, 
                n_epochs=5, gamma=0.99, gae_lambda=0.95, clip_range=0.2, ent_coef=0.0, 
                vf_coef=0.5, max_grad_norm=0.5,
                tensorboard_log=None, seed=seed, device=device,
                policy_kwargs=policy_kwargs)

    return agent, env

class GymAgent:
    def __init__(self, algo, seed, args):
        self.agent, self.env = make_array_agent(algo, seed, args)
        self.seed = seed
        self.args = args
        self.env_name = args.env_name
        self.n_timesteps = args.n_timesteps

    def get_action(self, obs):
        action, _states = self.agent.predict(obs, deterministic=True)
        # print("Action agent", action, "\n")
        return action

    def train(self):
        print('==' * 20, 'policy structure ==>', self.agent.policy)
        print('==' * 20, 'number of parameters: %d' % sum(p.numel() for p in self.agent.policy.parameters()))
        print('==' * 20, 'observation_space.shape ==>', self.agent.get_env().observation_space.shape)

        # train agent
        self.agent.learn(total_timesteps=self.n_timesteps)
    
    def test(self):    
        # test agent
        obs = self.env.reset()
        for i in range(2000):
            action, _states = self.agent.predict(obs, deterministic=True)
            # print(action)
            # print(_states)
            obs, reward, done, info = self.env.step(action)
            print(f"Testing Step: {i}, Action: {action}, Reward: {reward}, Done: {done}")
            # print(obs)
            if done:
                obs = self.env.reset()
        self.env.close()
    
    def save_model(self):
        save_path = self.args.log_folder + self.env_name + '__' + self.args.algo + '__' + str(self.seed) + '__running'
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        self.agent.save(save_path) # model = PPO.load("path/to/your_model.zip")
        
    def load_model(self):
        self.agent = PPO.load("/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/log/Ns3-v0__enhanced_tit_ppo__42__running.zip")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-name", type=str, default="Ns3-v0")
    parser.add_argument("--algo", type=str, default="enhanced_tit_ppo",
        choices=['vanilla_tit_ppo', 'enhanced_tit_ppo'])
    parser.add_argument("--device", type=str, default="auto")
    parser.add_argument("--log_folder", type=str, default="/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/log/")
    parser.add_argument("--n-timesteps", type=int, default=2000)
    parser.add_argument("--patch-dim", type=int, default=6)
    parser.add_argument("--num-blocks", type=int, default=2)
    parser.add_argument("--features-dim", type=int, default=64)
    parser.add_argument("--embed-dim-inner", type=int, default=8)
    parser.add_argument("--num-heads-inner", type=int, default=4)
    parser.add_argument("--attention-dropout-inner", type=float, default=0.0)
    parser.add_argument("--ffn-dropout-inner", type=float, default=0.0)
    parser.add_argument("--embed-dim-outer", type=int, default=64)
    parser.add_argument("--num-heads-outer", type=int, default=4)
    parser.add_argument("--attention-dropout-outer", type=float, default=0.0)
    parser.add_argument("--ffn-dropout-outer", type=float, default=0.0)
    parser.add_argument("--activation-fn-inner", default=None)
    parser.add_argument("--activation-fn-outer", default=None)
    parser.add_argument("--activation-fn-other", default=None)
    args = parser.parse_args()
    args = update_args(args) 
    agent = GymAgent(args.algo, 42, args)
    agent.train()
    agent.save_model()
    # agent.load_model()
    agent.test()
   
