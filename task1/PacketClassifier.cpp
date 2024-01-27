#include "PacketClassifier.h"

PacketClassifier* PacketClassifier::instance = nullptr;

PacketClassifier::PacketClassifier(const char* filename) {
    pcap = nullptr;
    g_running = 1;

    cout << "output файл: " << filename << endl;
    csvFile.open(filename);

    if (!csvFile.is_open()) {
        cerr << "Не удалось открыть файл: " << filename << endl;
    } else {
        csvFile << "Source IP,Source Port,Destination IP,Destination Port,Packet Count,Byte Count\n";
    }

    
}

PacketClassifier* PacketClassifier::getInstance(const char* filename) {
    if (!instance) {
        instance = new PacketClassifier(filename);
    }
    return instance;
}

PacketClassifier::~PacketClassifier() {
    csvFile.close();
}

void PacketClassifier::packetHandler(const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    struct iphdr* ipHeader = (struct iphdr*)(packetData + 14);

    if (ipHeader->version == 4) {
        if (ipHeader->protocol == IPPROTO_TCP) {
            processTCP(pkthdr, packetData);
        } else if (ipHeader->protocol == IPPROTO_UDP) {
            processUDP(pkthdr, packetData);
        }
    }
}

void PacketClassifier::processTCP(const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    struct iphdr* ipHeader = (struct iphdr*)(packetData + 14);
    struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + 14 + ipHeader->ihl * 4);

    uint32_t srcIP = ntohl(ipHeader->saddr);
    uint32_t destIP = ntohl(ipHeader->daddr);
    uint16_t srcPort = ntohs(tcpHeader->source);
    uint16_t destPort = ntohs(tcpHeader->dest);

    string streamKey = to_string(srcIP) + ":" + to_string(srcPort) + "-" + to_string(destIP) + ":" + to_string(destPort);

    streamData[streamKey].first++;
    streamData[streamKey].second += pkthdr->len;

    cout << "TCP Packet - Source IP: " << srcIP << ", Source Port: " << srcPort << 
        ", Destination IP: " << destIP << ", Destination Port: " << destPort << endl;
}

void PacketClassifier::processUDP(const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    struct iphdr* ipHeader = (struct iphdr*)(packetData + 14);
    struct udphdr* udpHeader = (struct udphdr*)(packetData + 14 + ipHeader->ihl * 4);

    uint32_t srcIP = ntohl(ipHeader->saddr);
    uint32_t destIP = ntohl(ipHeader->daddr);
    uint16_t srcPort = ntohs(udpHeader->source);
    uint16_t destPort = ntohs(udpHeader->dest);

    string streamKey = to_string(srcIP) + ":" + to_string(srcPort) + "-" + to_string(destIP) + ":" + to_string(destPort);

    streamData[streamKey].first++;
    streamData[streamKey].second += pkthdr->len;

    cout << "UDP Packet - Source IP: " << srcIP << ", Source Port: " << srcPort << 
        ", Destination IP: " << destIP << ", Destination Port: " << destPort << endl;
}

void PacketClassifier::processPackets(const char* mode, const char* interfaceOrFile) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (strncmp(mode, "1", 1) == 0) {
        pcap = pcap_open_live(interfaceOrFile, BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
            cerr << "Ошибка открытия сетевого интерфейса: " << errbuf << endl;
            return;
        }
        cout << "Захват пакетов с сетевого интерфейса " << interfaceOrFile << endl;

        signal(SIGINT, [](int signum) {
            if (instance) {
                instance->g_running = 0;
                pcap_breakloop(instance->pcap);
            }
        });

        while (g_running) {
            pcap_dispatch(pcap, 0, packetHandlerWrapper, reinterpret_cast<u_char*>(this));
        }

    } else if (strncmp(mode, "2", 1) == 0) {
        pcap = pcap_open_offline(interfaceOrFile, errbuf);
        if (pcap == NULL) {
            cerr << "Ошибка открытия файла: " << errbuf << endl;
            return;
        }
        cout << "Чтение пакетов из pcap файла " << interfaceOrFile << endl;

        pcap_loop(pcap, 0, packetHandlerWrapper, reinterpret_cast<u_char*>(this));

    } else {
        cerr << "Неверный режим" << endl << "1 - режим захвата пакетов с сетевого интерфейса\n" <<
            "2 - режим чтение пакетов из pcap файла\n";
        return;
    }

    pcap_close(pcap);
    writeCSV();
}

void PacketClassifier::packetHandlerWrapper(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    PacketClassifier* classifier = reinterpret_cast<PacketClassifier*>(userData);
    classifier->packetHandler(pkthdr, packetData);
}

void PacketClassifier::writeCSV() {
    cout << endl;
    for (const auto& entry : streamData) {
        size_t pos = entry.first.find("-");

        string src = entry.first.substr(0, pos);
        size_t delimiterPos = src.find(':');
        string srcIP = src.substr(0, delimiterPos);
        string srcPort = src.substr(delimiterPos + 1);

        string dest = entry.first.substr(pos + 1);
        size_t delimiterPos2 = dest.find(':');
        string destIP = dest.substr(0, delimiterPos2);
        string destPort = dest.substr(delimiterPos2 + 1);

        cout << srcIP << "," << destIP << "," << srcPort << "," << destPort << ","
            << entry.second.first << "," << entry.second.second << "\n";

        csvFile << srcIP << "," << destIP << "," << srcPort << "," << destPort << "," 
            << entry.second.first << "," << entry.second.second << "\n";
    }
    csvFile.flush();
}