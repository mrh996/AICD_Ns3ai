/*       
 * LICENSE : GNU General Public License v3.0 (https://github.com/Saket-Upadhyay/ns3-cybersecurity-simulations/blob/master/LICENSE)
 * REPOSITORY : https://github.com/Saket-Upadhyay/ns3-cybersecurity-simulations
 * =================================================================================
 * 
 * In this we follow the following setup / node placement
 * 
 *    (n1)
 *      \
 *       \
 *         -------- (n2) -------- (n3)
 *                 / |  \
 *                /  |   \ 
 *               /   |    \
 *             (B0),(B2)...(Bn) 
 *                 
 *  N0 is legitimate user, communicating with server N2 (data server) via node N1 (maybe website server interface )
 *  B0-Bn are bots DDoS-ing the network.
 * 
 * NetAnim XML is saved as -> DDoSim.xml 
 * 
 * Modify: Valerio Selis <v.selis@liverpool.ac.uk>
 *  
 */
#include <ns3/csma-helper.h>
#include <ns3/ai-module.h>
#include "ns3/mobility-module.h"
#include "ns3/nstime.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/netanim-module.h"

#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"

#include "ns3gymenv.h"

#include <iostream>

#define TCP_SINK_PORT 9000
#define UDP_SINK_PORT 9001

//experimental parameters
#define MAX_BULK_BYTES 100000
#define DDOS_RATE "20480kb/s"
#define MAX_SIMULATION_TIME 10.0

//Number of Bots for DDoS
#define NUMBER_OF_BOTS 10

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DDoSAttack");

/*
Monitor the flows and exchange info with the Gym env
*/
void Monitor (FlowMonitorHelper *fmh, Ptr<FlowMonitor> fm, NodeContainer nodes, Ptr<Ns3GymEnv> nge)
{
    //Print per flow statistics
    fm->CheckForLostPackets ();

    // Get the sink node
    Ptr<Node> node = nodes.Get(2);

    // Get the Ipv4 object associated with the sink node
    Ptr<Ipv4> ipv4_obj = node->GetObject<Ipv4>();

    // Get the IPv4 address of the sink node
    Ipv4Address ipv4_address = ipv4_obj->GetAddress(1, 0).GetLocal();

    // Obtain stats about the flows
    std::map<FlowId, FlowMonitor::FlowStats> flowStats = fm->GetFlowStats ();
    Ptr<Ipv4FlowClassifier> ifc = DynamicCast<Ipv4FlowClassifier> (fmh->GetClassifier ());
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator fs = flowStats.begin (); fs != flowStats.end (); ++fs)
    {
        Ipv4FlowClassifier::FiveTuple ft = ifc->FindFlow (fs->first);
        // Retrieve flow stats for the sink node
        if (ft.destinationAddress == Ipv4Address(ipv4_address)){
            std::cout << "\n\nFlow: " << ft.sourceAddress << " -> " << ft.destinationAddress << std::endl;
            nge->SetStats(fs->second.rxPackets);
            std::cout << "rxPackets: " << fs->second.rxPackets << ";";
            // Notify for new flow stats and get action(s) from Gym env
            std::cout << "get_action: " << nge->NotifyGetAction() << ";";
        }
    }
    // Schedule after one second
    Simulator::Schedule (Seconds(1), &Monitor, fmh, fm, nodes, nge);
}

int main(int argc, char *argv[])
{
    CommandLine cmd;
    cmd.Parse(argc, argv);

    Time::SetResolution(Time::NS);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    // OpenGym Env --- has to be created before any other thing
    Ptr<OpenGymInterface> openGymInterface = OpenGymInterface::Get();
    Ptr<Ns3GymEnv> nge = CreateObject<Ns3GymEnv>();

    //Legitimate connection bots
    NodeContainer nodes;
    nodes.Create(3);

    //Nodes for attack bots
    NodeContainer botNodes;
    botNodes.Create(NUMBER_OF_BOTS);

    // Define the Point-To-Point Links and their Paramters
    PointToPointHelper pp1, pp2;
    pp1.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pp1.SetChannelAttribute("Delay", StringValue("1ms"));

    pp2.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pp2.SetChannelAttribute("Delay", StringValue("1ms"));

    // Install the Point-To-Point Connections between Nodes
    NetDeviceContainer d02, d12, botDeviceContainer[NUMBER_OF_BOTS];
    d02 = pp1.Install(nodes.Get(0), nodes.Get(1));
    d12 = pp1.Install(nodes.Get(1), nodes.Get(2));

    for (int i = 0; i < NUMBER_OF_BOTS; ++i)
    {
        botDeviceContainer[i] = pp2.Install(botNodes.Get(i), nodes.Get(1));
    }

    pp1.EnablePcapAll("capture_pp1");
    pp2.EnablePcapAll("capture_pp2");

    //Assign IP to bots
    InternetStackHelper stack;
    stack.Install(nodes);
    stack.Install(botNodes);
    Ipv4AddressHelper ipv4_n;
    ipv4_n.SetBase("10.0.0.0", "255.255.255.252");

    Ipv4AddressHelper a02, a12, a23, a34;
    a02.SetBase("10.1.1.0", "255.255.255.0");
    a12.SetBase("10.1.2.0", "255.255.255.0");

    for (int j = 0; j < NUMBER_OF_BOTS; ++j)
    {
        ipv4_n.Assign(botDeviceContainer[j]);
        ipv4_n.NewNetwork();
    }

    //Assign IP to legitimate nodes
    Ipv4InterfaceContainer i02, i12;
    i02 = a02.Assign(d02);
    i12 = a12.Assign(d12);

    // DDoS Application Behaviour
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i12.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(DDOS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp[NUMBER_OF_BOTS];

    //Install application in all bots
    for (int k = 0; k < NUMBER_OF_BOTS; ++k)
    {
        onOffApp[k] = onoff.Install(botNodes.Get(k));
        onOffApp[k].Start(Seconds(0.0));
        onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
    }

    // Sender Application (Packets generated by this application are throttled)
    BulkSendHelper bulkSend("ns3::TcpSocketFactory", InetSocketAddress(i12.GetAddress(1), TCP_SINK_PORT));
    bulkSend.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));
    ApplicationContainer bulkSendApp = bulkSend.Install(nodes.Get(0));
    bulkSendApp.Start(Seconds(0.0));
    bulkSendApp.Stop(Seconds(MAX_SIMULATION_TIME - 10));

    // UDPSink on receiver side
    PacketSinkHelper UDPsink("ns3::UdpSocketFactory",
                             Address(InetSocketAddress(Ipv4Address::GetAny(), UDP_SINK_PORT)));
    ApplicationContainer UDPSinkApp = UDPsink.Install(nodes.Get(2));
    UDPSinkApp.Start(Seconds(0.0));
    UDPSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // TCP Sink Application on server side
    PacketSinkHelper TCPsink("ns3::TcpSocketFactory",
                             InetSocketAddress(Ipv4Address::GetAny(), TCP_SINK_PORT));
    ApplicationContainer TCPSinkApp = TCPsink.Install(nodes.Get(2));
    TCPSinkApp.Start(Seconds(0.0));
    TCPSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    //Simulation NetAnim configuration and node placement
    MobilityHelper mobility;

    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0), "MinY", DoubleValue(0.0), "DeltaX", DoubleValue(5.0), "DeltaY", DoubleValue(10.0),
                                  "GridWidth", UintegerValue(5), "LayoutType", StringValue("RowFirst"));

    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    mobility.Install(nodes);
    mobility.Install(botNodes);

    
    AnimationInterface anim("DDoSim.xml");
    anim.SetMaxPktsPerTraceFile(50000000);

    ns3::AnimationInterface::SetConstantPosition(nodes.Get(0), 0, 0);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(1), 10, 10);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(2), 20, 10);

    uint32_t x_pos = 0;
    for (int l = 0; l < NUMBER_OF_BOTS; ++l)
    {
        ns3::AnimationInterface::SetConstantPosition(botNodes.Get(l), x_pos++, 30);
    }

    // Monitor the flow(s) and export stats to XML
    FlowMonitorHelper fmh;
    Ptr<FlowMonitor> fm = fmh.InstallAll();
    fm->SerializeToXmlFile ("flowmonitor.xml", true, true);
    Monitor(&fmh, fm, nodes, nge);

    //Run the Simulation
    Simulator::Stop(Seconds(MAX_SIMULATION_TIME));
    Simulator::Run();

    openGymInterface->NotifySimulationEnd();

    Simulator::Destroy();
    return 0;
}