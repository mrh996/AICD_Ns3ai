import torch
import ns3ai_gym_env
import gymnasium as gym

import numpy as np
import random
import os
from collections import defaultdict
import pandas as pd
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import seaborn as sns
import torch

np.random.seed(42)
random.seed(42)
torch.manual_seed(42)

# conda activate ns3ai_env
# cd ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/use-gym/
# python run_ddosim_Qtable.py > /LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/QTable_result/train_QTable_0309.log

class ClusteredQLearning:
    def __init__(self, state_dim, action_dim, num_clusters=10, learning_rate=0.1, discount_factor=0.99, 
                 exploration_rate=1.0, exploration_decay=0.995, min_exploration_rate=0.01):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        self.exploration_decay = exploration_decay
        self.min_exploration_rate = min_exploration_rate
        self.num_clusters = num_clusters
        
        # init KMeans
        self.kmeans = KMeans(n_clusters=num_clusters, random_state=42)
        self.fitted = False
        
        # use defaultdict to handle unseen states
        self.q_table = defaultdict(lambda: np.zeros(action_dim))
        
        # keep track of cluster centers
        self.cluster_centers_history = []
        
        # save observed states for clustering
        self.observed_states = []
        
        # track state to cluster mapping
        self.state_to_cluster = {}
        
        # record cluster visit counts
        self.cluster_visit_counts = np.zeros(num_clusters)
        
        # save training data
        self.training_data = {
            'episode': [],
            'total_reward': [],
            'exploration_rate': [],
            'q_table_size': []
        }
    
    def _get_state_cluster(self, state):
        """将状态映射到相应的聚类"""
        if not self.fitted:
            return 0  # if not fitted, return the first cluster
        
        # state to features
        features = self._extract_features(state)
        
        # use cached mapping if available
        state_tuple = tuple(state)
        if state_tuple in self.state_to_cluster:
            return self.state_to_cluster[state_tuple]
        
        # predict cluster
        cluster_id = self.kmeans.predict([features])[0]
        
        # save mapping
        self.state_to_cluster[state_tuple] = cluster_id
        
        # update visit count
        self.cluster_visit_counts[cluster_id] += 1
        
        return cluster_id
    
    def _extract_features(self, state):
        """extract features from state
        """
        features = np.array(state).astype(float)
        
        # extract features
        features_dict = {
            'sim_time': state[0],
            'flow_count': state[1],
            'tx_bytes': state[2],
            'rx_bytes': state[3],
            'tx_packets': state[4],
            'rx_packets': state[5],
            'dropped_packets': state[6],
            'delay': state[7],
            'jitter': state[8],
            'throughput': state[9],
            'pdr': state[10],
            'plr': state[11]
        }
        
        # 1. scale features
        normalized_features = []
        
        normalized_features.append(np.log1p(features_dict['sim_time']))
        
        normalized_features.append(min(features_dict['flow_count'] / 1000, 1.0))
        
        if features_dict['tx_bytes'] > 0:
            normalized_features.append(features_dict['rx_bytes'] / features_dict['tx_bytes'])
        else:
            normalized_features.append(0)
            
        if features_dict['tx_packets'] > 0:
            normalized_features.append(features_dict['rx_packets'] / features_dict['tx_packets'])
        else:
            normalized_features.append(0)
        
        normalized_features.append(features_dict['plr'])  
        normalized_features.append(features_dict['pdr'])  
        
        normalized_features.append(min(features_dict['delay'] / 1000, 1.0))
        
        normalized_features.append(min(features_dict['jitter'] / 500, 1.0))
        
        normalized_features.append(min(features_dict['throughput'] / (1024 * 1024 * 1024 / 8), 1.0))
        
        return normalized_features
    
    def update_clusters(self, force=False):
        """update clusters using observed states"""
        if len(self.observed_states) < max(30, self.num_clusters * 3) and not force:
            return False
        
        # extract features
        features = np.array([self._extract_features(state) for state in self.observed_states])
        
        # do clustering
        self.kmeans.fit(features)
        self.fitted = True
        
        # save cluster centers
        self.cluster_centers_history.append(self.kmeans.cluster_centers_.copy())
        
        # reset state to cluster mapping
        self.state_to_cluster = {}
        
        # reset visit counts
        self.cluster_visit_counts = np.zeros(self.num_clusters)
        
        print(f"Updated clusters with {len(self.observed_states)} states", flush=True)
        return True
    
    def choose_action(self, state):
        """choose action based on epsilon-greedy policy"""
        if np.random.random() < self.exploration_rate:
            # explore: choose random action
            return np.random.randint(self.action_dim)
        else:
            # exploit: choose best action
            cluster_id = self._get_state_cluster(state)
            return np.argmax(self.q_table[cluster_id])
    
    def update(self, state, action, reward, next_state, done):
        """更新Q表"""
        # save observed states
        self.observed_states.append(state)
        
        # get state clusters
        current_cluster = self._get_state_cluster(state)
        next_cluster = self._get_state_cluster(next_state)
        
        # current Q value
        current_q = self.q_table[current_cluster][action]
        
        # calculate target Q value
        max_next_q = np.max(self.q_table[next_cluster])
        target_q = reward + (self.discount_factor * max_next_q * (1 - done))
        
        # update Q value
        self.q_table[current_cluster][action] += self.learning_rate * (target_q - current_q)
        
    
    def save_model(self, filepath):
        """save model to file"""
        model_data = {
            'q_table': dict(self.q_table),
            'kmeans_centers': self.kmeans.cluster_centers_ if self.fitted else None,
            'exploration_rate': self.exploration_rate,
            'observed_states': self.observed_states,
            'state_to_cluster': self.state_to_cluster,
            'cluster_visit_counts': self.cluster_visit_counts,
            'training_data': self.training_data
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        np.save(filepath, model_data)
        print(f"Model saved to {filepath}", flush=True)
    

    def load_model(self, filepath):
        try:
            model_data = np.load(filepath, allow_pickle=True).item()
            
            # restore Q table
            self.q_table = defaultdict(lambda: np.zeros(self.action_dim))
            for k, v in model_data['q_table'].items():
                self.q_table[k] = v
            
            # restore KMeans object
            if model_data['kmeans_centers'] is not None:
                from sklearn.cluster import KMeans
                # create new KMeans object
                new_kmeans = KMeans(n_clusters=self.num_clusters, random_state=42)
                
                # set dummy data to fit the object
                dummy_X = np.random.random((self.num_clusters*2, len(model_data['kmeans_centers'][0])))
                new_kmeans.fit(dummy_X)
                
                # replace the cluster centers
                new_kmeans.cluster_centers_ = model_data['kmeans_centers']
                
                # replace the old KMeans object
                self.kmeans = new_kmeans
                self.fitted = True
            
            # restore other data
            self.exploration_rate = model_data['exploration_rate']
            self.observed_states = model_data['observed_states']
            self.state_to_cluster = model_data['state_to_cluster']
            self.cluster_visit_counts = model_data['cluster_visit_counts']
            self.training_data = model_data['training_data']
            
            print(f"Model loaded from {filepath}", flush=True)
            return True
        except (FileNotFoundError, ValueError) as e:
            print(f"Failed to load model: {e}", flush=True)
            return False
    
    def plot_training_progress(self, save_path=None):
        """plot training progress"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # 1. reward per episode
        axes[0, 0].plot(self.training_data['episode'], self.training_data['total_reward'])
        axes[0, 0].set_title('Total Reward per Episode')
        axes[0, 0].set_xlabel('Episode')
        axes[0, 0].set_ylabel('Total Reward')
        
        # 2. exploration rate
        axes[0, 1].plot(self.training_data['episode'], self.training_data['exploration_rate'])
        axes[0, 1].set_title('Exploration Rate per Episode')
        axes[0, 1].set_xlabel('Episode')
        axes[0, 1].set_ylabel('Exploration Rate')
        
        # 3. change in Q-table size
        axes[1, 0].plot(self.training_data['episode'], self.training_data['q_table_size'])
        axes[1, 0].set_title('Q-Table Size per Episode')
        axes[1, 0].set_xlabel('Episode')
        axes[1, 0].set_ylabel('Number of States in Q-Table')
        
        # 4. cluster visit frequency
        if self.fitted:
            axes[1, 1].bar(range(self.num_clusters), self.cluster_visit_counts)
            axes[1, 1].set_title('Cluster Visit Frequency')
            axes[1, 1].set_xlabel('Cluster ID')
            axes[1, 1].set_ylabel('Visit Count')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
            print(f"Training progress plot saved to {save_path}", flush=True)
        
        plt.show()
        
    def display_q_table(self, top_n=None, save_path=None):
        """
        display Q-table as heatmap
        
        Args:
            top_n (int): number of top states to display
            save_path (str): path to save the heatmap
        """
        if not self.q_table:
            print("Empty Q Tab;e", flush=True)
            return
            
        # transform Q-table to DataFrame
        q_data = []
        for cluster_id, q_values in self.q_table.items():
            # check visit count
            visit_count = self.cluster_visit_counts[cluster_id] if self.fitted else 0
            
            # get best action
            best_action = np.argmax(q_values)
            
            # add row
            row = {
                "Cluster ID": cluster_id,
                "Visit Count": visit_count,
                "Action 0 (Observe)": q_values[0],
                "Action 1 (Add Suspicious)": q_values[1],
                "Action 2 (Remove Suspicious)": q_values[2],
                "Action 3 (Promote Blacklist)": q_values[3],
                "Best Action": best_action,
                "Max Q-Value": np.max(q_values)
            }
            q_data.append(row)
            
        q_df = pd.DataFrame(q_data)
        
        if top_n is not None and self.fitted:
            q_df = q_df.sort_values("Visit Count", ascending=False).head(top_n)
            
        # sort by cluster ID
        q_df = q_df.sort_values("Cluster ID").reset_index(drop=True)
        
        # print Q-table
        print("\n===== Q-Table =====", flush=True)
        print(q_df, flush=True)
        print(f"Q Table Size: {len(self.q_table)} clusters", flush=True)
        
        # plot Q-table as heatmap
        plt.figure(figsize=(12, max(6, len(q_df) * 0.4)))
        
        # get Q-values columns
        q_values_columns = [col for col in q_df.columns if col.startswith("Action")]
        heat_data = q_df[q_values_columns].values
        
        # plot heatmap
        sns.heatmap(heat_data, 
                   annot=True, 
                   fmt=".2f",
                   cmap="viridis",
                   yticklabels=q_df["Cluster ID"].values,
                   xticklabels=[col.split("(")[1][:-1] for col in q_values_columns],
                   cbar_kws={'label': 'Q-Value'})
        
        plt.title("Q-Values heatmap(cluster ID)")
        plt.ylabel("Cluster ID")
        plt.xlabel("Action")
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
            print(f"Q-table heatmap saved in {save_path}", flush=True)
            
        plt.show()
        
        # draw best action distribution
        plt.figure(figsize=(10, 6))
        action_counts = q_df["Best Action"].value_counts().sort_index()
        bars = plt.bar(action_counts.index, action_counts.values)
        
        # add labels
        action_names = ["Observe", "Add Suspicious", "Remove Suspicious", "Promote Blacklist"]
        plt.xticks(range(4), action_names, rotation=45)
        plt.title("Best Action Distribution")
        plt.xlabel("Action")
        plt.ylabel("Count")
        
        # display counts on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    str(height), ha='center', va='bottom')
        
        plt.tight_layout()
        
        if save_path:
            base, ext = os.path.splitext(save_path)
            plt.savefig(f"{base}_action_dist{ext}")
            
        plt.show()
        
        return q_df
        
    def analyze_q_table_by_plr(self, save_path=None):
        """
        analyze Q-table by Packet Loss Rate (PLR)
        """
        if not self.fitted or len(self.observed_states) == 0:
            print("Not Training Yet", flush=True)
            return
            
        # extract PLR and cluster ID for each state
        state_plr_clusters = []
        for state in self.observed_states:
            features = self._extract_features(state)
            plr = state[11]  # PLR
            cluster_id = self._get_state_cluster(state)
            state_plr_clusters.append((plr, cluster_id))
            
        # group states by PLR range
        plr_ranges = [0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.8, 1.0]
        plr_groups = {}
        
        for plr, cluster_id in state_plr_clusters:
            for i in range(len(plr_ranges)-1):
                if plr_ranges[i] <= plr < plr_ranges[i+1]:
                    group_name = f"{plr_ranges[i]}-{plr_ranges[i+1]}"
                    if group_name not in plr_groups:
                        plr_groups[group_name] = []
                    plr_groups[group_name].append(cluster_id)
                    break
        
        # analyze Q-table for each PLR range
        plr_action_dist = {}
        for group_name, cluster_ids in plr_groups.items():
            # calculate action distribution
            action_counts = np.zeros(self.action_dim)
            
            for cluster_id in set(cluster_ids):  # remove duplicates
                if cluster_id in self.q_table:
                    best_action = np.argmax(self.q_table[cluster_id])
                    action_counts[best_action] += 1
                    
            # normalize to get distribution
            if sum(action_counts) > 0:
                action_dist = action_counts / sum(action_counts)
                plr_action_dist[group_name] = action_dist
            else:
                plr_action_dist[group_name] = np.zeros(self.action_dim)
        
        action_names = ["Observe", "Add Suspicious", "Remove Suspicious", "Promote Blacklist"]
        plr_df = pd.DataFrame(plr_action_dist, index=action_names).T
        
        # print and plot
        print("\n===== Best action distribution for different PLR =====", flush=True)
        print(plr_df, flush=True)
        plt.figure(figsize=(12, 6))
        plr_df.plot(kind='bar', stacked=True, colormap='viridis')
        plt.title('Different PLR Ranges and Action Distribution')
        plt.xlabel('PLR Range')
        plt.ylabel('Action Distribution')
        plt.legend(title='Action')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
            print(f"PLR Analysis in {save_path}", flush=True)
            
        plt.show()
        
        return plr_df

    def record_episode_data(self, episode, total_reward):
        """record training data"""
        self.training_data['episode'].append(episode)
        self.training_data['total_reward'].append(total_reward)
        self.training_data['exploration_rate'].append(self.exploration_rate)
        self.training_data['q_table_size'].append(len(self.q_table))

# 主训练循环
def train_ddos_defense(env, agent, num_episodes=1000, max_steps=1000, 
                       save_interval=100, model_dir="models"):
    """train DDoS defense agent"""
    os.makedirs(model_dir, exist_ok=True)
    
    best_reward = float('-inf')
    episode_rewards = []
    
    for episode in range(num_episodes):
        state = env.reset()
        state = state[0] if isinstance(state, tuple) else state
        total_reward = 0
        done = False
        step = 0
        
        while not done and step < max_steps:
            action = agent.choose_action(state)
            next_state, reward, done, _, info = env.step(action)
            
            # update Q-table
            agent.update(state, action, reward, next_state, done)
            
            # reward
            total_reward += reward
            
            # update state
            state = next_state
            step += 1
            
            # update clusters
            if step % 15 == 0:
                agent.update_clusters()
        
        # decay exploration rate
        agent.exploration_rate = max(
            agent.min_exploration_rate, 
            agent.exploration_rate * agent.exploration_decay
        )
        
        # record training data
        agent.record_episode_data(episode, total_reward)
        episode_rewards.append(total_reward)
        
        # print results
        print(f"Episode {episode+1}/{num_episodes}, Total Reward: {total_reward:.2f}, " 
              f"Exploration Rate: {agent.exploration_rate:.4f}, "
              f"Q-Table Size: {len(agent.q_table)}", flush=True)
        
        # update clusters more frequently
        if (episode + 1) % 5 == 0:  # update every 5 episodes
            agent.update_clusters(force=True)
        
        # save model
        if (episode + 1) % save_interval == 0:
            agent.save_model(f"{model_dir}/ddos_defense_ep{episode+1}.npy")
        
        if total_reward > best_reward:
            best_reward = total_reward
            agent.save_model(f"{model_dir}/ddos_defense_best.npy")
    
    agent.save_model(f"{model_dir}/ddos_defense_final.npy")
    
    agent.plot_training_progress(f"{model_dir}/training_progress.png")
    
    return episode_rewards

# test DDoS defense agent
def test_ddos_defense(env, agent, num_episodes=10, max_steps=1000):
    test_rewards = []
    
    for episode in range(num_episodes):
        state = env.reset()
        state = state[0] if isinstance(state, tuple) else state
        total_reward = 0
        done = False
        step = 0
        actions_taken = {i: 0 for i in range(agent.action_dim)}
        
        while not done and step < max_steps:
            action = agent.choose_action(state)
            actions_taken[action] += 1
            
            next_state, reward, done, _, info = env.step(action)
            
            total_reward += reward
            
            state = next_state
            step += 1
        
        test_rewards.append(total_reward)
        
        print(f"Test Episode {episode+1}/{num_episodes}, Total Reward: {total_reward:.2f}", flush=True)
        print(f"Actions taken: {actions_taken}", flush=True)
    
    avg_reward = sum(test_rewards) / len(test_rewards)
    print(f"Average Reward over {num_episodes} test episodes: {avg_reward:.2f}", flush=True)
    
    return test_rewards


def load_and_test_model():
    # create NS-3 AI Gym environment
    env = gym.make("ns3ai_gym_env/Ns3-v0", targetName="ns3ai_ddos_gym", ns3Path="../../../../../")
    
    # get state/action space
    ob_space = env.observation_space  
    ac_space = env.action_space       
    state_dim = ob_space.shape[0]   
    action_dim = ac_space.n         
    print(f"State space: {ob_space}, Action space: {ac_space}")
    
    # create agent
    agent = ClusteredQLearning(
        state_dim=state_dim,
        action_dim=action_dim,
        num_clusters=15,                
        learning_rate=0.05,             
        discount_factor=0.9,          
        exploration_rate=1.0,         
        exploration_decay=0.995,       
        min_exploration_rate=0.1      
    )
    
    # load model
    model_path = "/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/ddos_defense_models/0309/ddos_defense_final.npy"
    success = agent.load_model(model_path)
    
    if not success:
        print("模型加载失败，请检查文件路径和文件是否存在")
        return
    
    # set exploration rate to minimum
    agent.exploration_rate = agent.min_exploration_rate
    
    # test agent
    test_rewards = test_ddos_defense(
        env=env,
        agent=agent,
        num_episodes=100,              
        max_steps=70                  
    )
    
    # analyze Q-table
    agent.display_q_table(save_path="/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/ddos_defense_models/0309/loaded_q_table_heatmap.png")
    agent.analyze_q_table_by_plr(save_path="/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/ddos_defense_models/0309/loaded_plr_analysis.png")
    
    print(f"Average Testing Reward: {sum(test_rewards)/len(test_rewards)}")
    

def main():
    env = gym.make("ns3ai_gym_env/Ns3-v0", targetName="ns3ai_ddos_gym", ns3Path="../../../../../")
    
    ob_space = env.observation_space  
    ac_space = env.action_space     
    state_dim = ob_space.shape[0]     
    action_dim = ac_space.n           
    print(f"State space: {ob_space}, Action space: {ac_space}", flush=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Using device:", device, flush=True)
    
    agent = ClusteredQLearning(
        state_dim=state_dim,
        action_dim=action_dim,
        num_clusters=15,                
        learning_rate=0.05,             
        discount_factor=0.9,         
        exploration_rate=1.0,       
        exploration_decay=0.995,         
        min_exploration_rate=0.1     
    )
    

    print("Starting training...", flush=True)
    train_rewards = train_ddos_defense(
        env=env,
        agent=agent,
        num_episodes=400,               
        max_steps=70,                 
        save_interval=1,            
        model_dir="/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/ddos_defense_models/0309" # 添加完整路径
    )

    
    # 测试代理
    print("\nStarting testing...", flush=True)
    test_rewards = test_ddos_defense(
        env=env,
        agent=agent,
        num_episodes=5,                
        max_steps=70                   
    )
    

    plt.figure(figsize=(12, 6))
    plt.plot(train_rewards)
    plt.title('Training Rewards')
    plt.xlabel('Episode')
    plt.ylabel('Total Reward')
    plt.savefig("/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/ddos_defense_models/0309/training_rewards.png")
    plt.show()
    
    # 显示和分析Q表
    print("\n===== QTable Analysis =====", flush=True)
    agent.display_q_table(save_path="/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/ddos_defense_models/0309/q_table_heatmap.png")
    agent.analyze_q_table_by_plr(save_path="/LOCAL2/sgjhu13/ns-allinone-3.41/ns-3.41/contrib/ai/examples/DDoS_v2/ddos_defense_models/0309/plr_action_analysis.png")
    
    print("Training and testing completed.", flush=True)

if __name__ == "__main__":
    # main()
    
    # only for testing
    load_and_test_model()