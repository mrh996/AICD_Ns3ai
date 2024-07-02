build_lib_example(
      NAME ns3ai_ddos_v2_gym
      SOURCE_FILES use-gym/sim.cc
      SOURCE_FILES use-gym/ns3gymenv.cc
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
