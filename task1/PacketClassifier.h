#pragma once

#include <pcap.h>
#include <iostream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <fstream>
#include <unordered_map>
#include <csignal>
#include <functional>
#include <atomic>

using namespace std;

class PacketClassifier {
private:
    unordered_map<string, pair<uint64_t, uint64_t>> streamData; // IP1:Port1-IP2:Port2 -> (packetCount, byteCount)
    ofstream csvFile;

    static PacketClassifier* instance;

    pcap_t *pcap;
    volatile sig_atomic_t g_running;

    PacketClassifier(const char* filename);

public:
    static PacketClassifier* getInstance(const char* filename);
    ~PacketClassifier();

    void packetHandler(const struct pcap_pkthdr* pkthdr, const u_char* packetData);
    void processTCP(const struct pcap_pkthdr* pkthdr, const u_char* packetData);
    void processUDP(const struct pcap_pkthdr* pkthdr, const u_char* packetData);
    void processPackets(const char* mode, const char* interfaceOrFile);
    static void packetHandlerWrapper(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData);
    void writeCSV();
};
