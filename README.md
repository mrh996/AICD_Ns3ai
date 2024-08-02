## Install the required Python 3 modules:

$ pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

$ pip3 install matplotlib cppyy==2.4.2 pygraphviz pycairo cxxfilt

##	Install and build ns3 with the ns3-ai module:

$ cd ~/

$ wget https://www.nsnam.org/releases/ns-allinone-3.41.tar.bz2

$ tar xjf ns-allinone-3.41.tar.bz2

$ cd ~/ns-allinone-3.41/ns-3.41/

$ git clone https://github.com/hust-diangroup/ns3-ai.git contrib/ai

$  replace the file in model/gym-interface/py/ns3ai_gym_env/envs/ns3_environment.py with the ns3_environment.py here

$ ./ns3 configure --enable-examples

$ ./ns3 build ai

$ pip3 install -e contrib/ai/python_utils

$ pip3 install -e contrib/ai/model/gym-interface/py

$ ./ns3 build ns3ai_apb_gym ns3ai_apb_msg_stru ns3ai_apb_msg_vec ns3ai_multibss ns3ai_rltcp_gym ns3ai_rltcp_msg ns3ai_ratecontrol_constant ns3ai_ratecontrol_ts ns3ai_ltecqi_msg

##	Install and build the crocs project files:

$ cd contrib/ai/examples/

$ wget https://www.dropbox.com/scl/fi/zv5ib8up3lmr2atjsv2sy/crocs_ns3_project.zip?rlkey=3r0iefy0n76emjfu0ozifzfql&st=k7xrz9wn&dl=0 -O crocs_ns3_project.zip


$ unzip crocs_ns3_project.zip

 When asked, click ‘y’ to replace the CMakeLists.txt file

## Or add the examples in current github project.

$ cd ../../../

$ PYTHONCONDAVER=$(ls /home/crocs/anaconda3/envs/ns3ai_env/include | grep python)  ( Get your environment's python version python --version)

$ ./ns3 configure --enable-python-bindings -- -DPython3_LIBRARY_DIRS=/LOCAL2/mur/.conda/envs/ns3ai_env/lib -DPython3_INCLUDE_DIRS=/LOCAL2/mur/.conda/envs/ns3ai_env/include/python3.10.14 ( Replace your python version here, mine is 3.10.14)


$ ./ns3 build ns3ai_ddos_gym

or

$ ./ns3 build ns3ai_ddos_v2_gym

Run the simulation:

$ cd contrib/ai/examples/DDoSim/use-gym/

or

$ cd contrib/ai/examples/DDoSim_v2/use-gym/

## Train a RL agent to form DDoS attack

python run_ddos_rl_attack.py




