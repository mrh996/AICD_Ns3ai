/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 *
 * Author: Valerio Selis <v.selis@liverpool.ac.uk>
 *
 */


#ifndef FEATURE_STRUCT_H
#define FEATURE_STRUCT_H

#include "ns3/flow-monitor.h"
#include "ns3/ipv4-flow-classifier.h"

namespace ns3 {

// Structure per each node include a list of flows with related features
struct FeaturesStruct {
    std::vector<FlowId> flowId;                  // Flow ID
    std::vector<double> simTime;
    std::vector<uint32_t> srcAddr;               // Source IPv4 address
    std::vector<uint32_t> dstAddr;               // Destination IPv4 address
    std::vector<uint16_t> srcPort;               // Source port
    std::vector<uint16_t> dstPort;               // Destination port
    std::vector<uint8_t> proto;                  // Protocol
    std::vector<double> timeFirstTxPacket;
    std::vector<double> timeLastTxPacket;
    std::vector<double> timeFirstRxPacket;
    std::vector<double> timeLastRxPacket;
    std::vector<uint32_t> txBytes;
    std::vector<uint32_t> rxBytes;
    std::vector<uint32_t> txPackets;
    std::vector<uint32_t> rxPackets;
    std::vector<uint32_t> forwardedPackets;
    std::vector<uint32_t> droppedPackets;
    std::vector<double> delaySum;
    std::vector<double> jitterSum;
    std::vector<double> lastDelay;
};

using FeaturesMap = std::unordered_map<int, FeaturesStruct>;
using ForwardedMap = std::unordered_map<uint32_t, std::vector<uint64_t>>;

} // namespace ns3

#endif // FEATURE_STRUCT_H