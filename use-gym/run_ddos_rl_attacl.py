import gymnasium as gym
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.vec_env import DummyVecEnv
import ns3ai_gym_env

class GymAgent:
    def __init__(self):
        pass

    def get_action(self, obs, reward, done, info):
        act = env.action_space.sample()
        return act

# Create the Gym environment
env = gym.make("ns3ai_gym_env/Ns3-v0", targetName="ns3ai_ddos_gym", ns3Path="../../../../../")

# Check if the environment is valid
check_env(env)

# Wrap the environment with DummyVecEnv for vectorized environment support
env = DummyVecEnv([lambda: env])

# Define the PPO model with reduced training parameters
model = PPO("MlpPolicy", env, verbose=1, learning_rate=0.001, n_steps=5, batch_size=2, n_epochs=5, gamma=0.99, gae_lambda=0.95, clip_range=0.2, ent_coef=0.0, vf_coef=0.5, max_grad_norm=0.5, tensorboard_log=None)

# Train the model for a smaller number of timesteps
model.learn(total_timesteps=1000)

# Save the trained model
model.save("ppo_ddos")
#model.load("ppo_ddos_gym")
# Test the trained model
obs = env.reset()
for i in range(10):
    action, _states = model.predict(obs, deterministic=True)
    obs, reward, done, info = env.step(action)
    print(f"Testing Step: {i}, Action: {action}, Reward: {reward}, Done: {done}")
    if done:
        obs = env.reset()

# Close the environment
env.close()
