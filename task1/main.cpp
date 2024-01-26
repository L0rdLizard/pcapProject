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

    // static pcap_t *pcap;
    // static volatile sig_atomic_t g_running;
    pcap_t *pcap;
    volatile sig_atomic_t g_running;

    PacketClassifier(const char* filename) {
        pcap = nullptr;
        g_running = 1;

        cout << filename << endl;
        csvFile.open(filename);

        if (!csvFile.is_open()) {
            cerr << "Не удалось открыть файл: " << filename << endl;
        } else {
            cout << "Файл открыт" << endl;
            csvFile << "Source IP,Source Port,Destination IP,Destination Port,Packet Count,Byte Count\n";
        }

        signal(SIGINT, [](int signum) {
            if (instance) {
                instance->g_running = 0;
                pcap_breakloop(instance->pcap);
                // writeCSV();
            }
        });
        
    }

    // static void handleSignal(int signum) {
    //     if (signum == SIGINT) {
    //         g_running = 0;
    //         pcap_breakloop(pcap);
    //     }
    // }

public:

    // static PacketClassifier* getInstance(const char* filename) {
    //     return new PacketClassifier(filename);
    // }

    static PacketClassifier* getInstance(const char* filename) {
        if (!instance) {
            instance = new PacketClassifier(filename);
        }
        return instance;
    }

    ~PacketClassifier() {
        csvFile.close();
    }

    void packetHandler(const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
        struct iphdr* ipHeader = (struct iphdr*)(packetData + 14);

        if (ipHeader->version == 4) {
            if (ipHeader->protocol == IPPROTO_TCP) {
                processTCP(pkthdr, packetData);
            } else if (ipHeader->protocol == IPPROTO_UDP) {
                processUDP(pkthdr, packetData);
            }
        }
    }

    void processTCP(const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
        struct iphdr* ipHeader = (struct iphdr*)(packetData + 14);
        struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + 14 + ipHeader->ihl * 4);

        uint32_t srcIP = ntohl(ipHeader->saddr);
        uint32_t destIP = ntohl(ipHeader->daddr);
        uint16_t srcPort = ntohs(tcpHeader->source);
        uint16_t destPort = ntohs(tcpHeader->dest);

        string streamKey = to_string(srcIP) + ":" + to_string(srcPort) + "-" + to_string(destIP) + ":" + to_string(destPort);

        streamData[streamKey].first++;
        streamData[streamKey].second += pkthdr->len;

        cout << "TCP Packet - Source IP: " << srcIP << ", Source Port: " << srcPort << ", Destination IP: " << destIP << ", Destination Port: " << destPort << endl;
    }

    void processUDP(const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
        struct iphdr* ipHeader = (struct iphdr*)(packetData + 14);
        struct udphdr* udpHeader = (struct udphdr*)(packetData + 14 + ipHeader->ihl * 4);

        uint32_t srcIP = ntohl(ipHeader->saddr);
        uint32_t destIP = ntohl(ipHeader->daddr);
        uint16_t srcPort = ntohs(udpHeader->source);
        uint16_t destPort = ntohs(udpHeader->dest);

        string streamKey = to_string(srcIP) + ":" + to_string(srcPort) + "-" + to_string(destIP) + ":" + to_string(destPort);

        streamData[streamKey].first++;
        streamData[streamKey].second += pkthdr->len;

        cout << "UDP Packet - Source IP: " << srcIP << ", Source Port: " << srcPort << ", Destination IP: " << destIP << ", Destination Port: " << destPort << endl;
    }

    void processPackets(const char* mode, const char* interfaceOrFile) {
        char errbuf[PCAP_ERRBUF_SIZE];
        // pcap_t* pcap;

        // signal(SIGINT, PacketClassifier::handleSignal);
        
        if (strncmp(mode, "1", 1) == 0) {
            // TODO live mode is broken
            pcap = pcap_open_live(interfaceOrFile, BUFSIZ, 1, 1000, errbuf);
            if (pcap == NULL) {
                cerr << "Ошибка открытия сетевого интерфейса: " << errbuf << endl;
                return;
            }
            cout << "Захват пакетов с сетевого интерфейса " << interfaceOrFile << endl;

            while (g_running) {
                pcap_dispatch(pcap, 0, packetHandlerWrapper, reinterpret_cast<u_char*>(this));
            }
            // while (g_running) {
            //     if (pcap_dispatch(pcap, 0, packetHandlerWrapper, reinterpret_cast<u_char*>(this)) == -1) {
            //         cerr << "Ошибка при вызове pcap_dispatch: " << pcap_geterr(pcap) << endl;
            //         break;
            //     }
            // }

        } else if (strncmp(mode, "2", 1) == 0) {
            pcap = pcap_open_offline(interfaceOrFile, errbuf);
            if (pcap == NULL) {
                cerr << "Ошибка открытия файла: " << errbuf << endl;
                return;
            }
            cout << "Чтение пакетов из pcap файла " << interfaceOrFile << endl;

            pcap_loop(pcap, 0, packetHandlerWrapper, reinterpret_cast<u_char*>(this));

        } else {
            cerr << "Неверный режим" << endl << "1 - режим захвата пакетов с сетевого интерфейса\n" << "2 - режим чтение пакетов из pcap файла\n";
            return;
        }

        
        cout << "end";

        // while (g_running) {
        //     pcap_dispatch(pcap, 0, packetHandlerWrapper, reinterpret_cast<u_char*>(this));
        // }

        // pcap_loop(pcap, 0, packetHandlerWrapper, reinterpret_cast<u_char*>(this));

        pcap_close(pcap);
        writeCSV();
    }

    static void packetHandlerWrapper(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
        PacketClassifier* classifier = reinterpret_cast<PacketClassifier*>(userData);
        classifier->packetHandler(pkthdr, packetData);
    }

    void writeCSV() {
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

            cout << srcIP << "," << destIP << "," << srcPort << "," << destPort << "," << entry.second.first << "," << entry.second.second << "\n";

            csvFile << srcIP << "," << destIP << "," << srcPort << "," << destPort << "," << entry.second.first << "," << entry.second.second << "\n";
        }
        csvFile.flush();
    }
};

// pcap_t* PacketClassifier::pcap;
// volatile sig_atomic_t PacketClassifier::g_running;  
PacketClassifier* PacketClassifier::instance = nullptr;


int main(int argc, char const* argv[]) {
    if (argc < 3) {
        cerr << "Использование: " << argv[0] << " <режим> <интерфейс или файл>" << endl << "1 - режим захвата пакетов с сетевого интерфейса\n" << "2 - режим чтение пакетов из pcap файла\n";
        return 1;
    }

    // PacketClassifier classifier("output.csv");
    // classifier.processPackets(argv[1], argv[2]);

    PacketClassifier* packetClassifierInstance = PacketClassifier::getInstance("output.csv");

    packetClassifierInstance->processPackets(argv[1], argv[2]);

    return 0;
}
