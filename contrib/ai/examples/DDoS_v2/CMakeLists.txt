build_lib_example(
      NAME ns3ai_ddos_gym
      SOURCE_FILES Transformer-RL/sim.cc
      SOURCE_FILES Transformer-RL/ns3gymenv.cc
      LIBRARIES_TO_LINK
        ${libcsma}
        ${libinternet}
        ${libapplications}
        ${libai}
        ${libcore}
        ${libpoint-to-point}
        ${libpoint-to-point-layout}
        ${libnetwork}
        ${libapplications}
        ${libmobility}
        ${libflow-monitor}
        ${libnetanim}
)
