/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 *  BSD 3-Clause License
 * 
 *  Copyright (c) 2025, University of Liverpool
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 * 
 *  1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 * 
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 * 
 *  3. Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 * 
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 *  Author: Ronghui Mu <ronghui.mu@liverpool.ac.uk>
 *  Author: Jinwei Hu <jinwei.hu@liverpool.ac.uk>
 *  Author: Valerio Selis <v.selis@liverpool.ac.uk>
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
    std::vector<uint32_t> lastTxBytes;
    std::vector<uint32_t> lastRxBytes;
    std::vector<uint32_t> lastTxPackets;
    std::vector<uint32_t> lastRxPackets;
    std::vector<uint32_t> lastLostPackets;
    std::vector<double> lastJitterSum;
    std::vector<double> lastDelaySum;

};

using FeaturesMap = std::unordered_map<int, FeaturesStruct>;
using ForwardedMap = std::unordered_map<uint32_t, std::vector<uint64_t>>;

struct AggregateFeatures {
    double simTime;
    uint32_t totalTxBytesInc;
    uint32_t totalRxBytesInc;
    uint32_t totalTxPacketsInc;
    uint32_t totalRxPacketsInc;
    uint32_t totalDroppedInc;
    double avgDelayInc;
    double avgJitterInc;
    uint32_t flowCount;
};

// Historical behavior statistics for each source address
struct SourceBehaviorStats {
    Ipv4Address destAddr;          // Destination address
    uint32_t activeCount;          // Active count (number of appearances in monitoring period)
    uint32_t totalMonitorCount;    // Total monitoring count
    uint32_t firstMonitorCount;    // First monitoring count
    double activeRatio;            // Active ratio
    uint32_t totalTxBytes;         // Total transmitted bytes
    uint32_t totalTxPackets;       // Total transmitted packets
    uint32_t totalRxBytes;         // Total transmitted bytes
    uint32_t totalRxPackets;       // Total transmitted packets
    uint32_t totalDroppedPackets;  // Total dropped packets
    double avgSendRate;            // Average sending rate (bytes/s)
    double firstSeenTime;          // Time first seen
    double lastSeenTime;           // Time last seen
    bool isActive;                 // Activity status
};


} // namespace ns3

#endif // FEATURE_STRUCT_H
