#include <pcap.h>
#include <iostream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {

    struct iphdr* ipHeader = (struct iphdr*)(packetData + 14); 
    
    if (ipHeader->version == 4) {

        if (ipHeader->protocol == IPPROTO_TCP) {
            struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + 14 + ipHeader->ihl * 4);

            uint16_t srcPort = ntohs(tcpHeader->source);
            uint16_t destPort = ntohs(tcpHeader->dest);

            uint32_t srcIP = ntohl(ipHeader->saddr);
            uint32_t destIP = ntohl(ipHeader->daddr);

            cout << "TCP Packet - Source IP: " << srcIP << ", Source Port: " << srcPort << ", Destination IP: " << destIP << ", Destination Port: " << destPort << endl;

        } else if (ipHeader->protocol == IPPROTO_UDP) {
            struct udphdr* udpHeader = (struct udphdr*)(packetData + 14 + ipHeader->ihl * 4);

            uint16_t srcPort = ntohs(udpHeader->source);
            uint16_t destPort = ntohs(udpHeader->dest);

            uint32_t srcIP = ntohl(ipHeader->saddr);
            uint32_t destIP = ntohl(ipHeader->daddr);

            cout << "UDP Packet - Source IP: " << srcIP << ", Source Port: " << srcPort << ", Destination IP: " << destIP << ", Destination Port: " << destPort << endl;

        }
    }
}


int main(int argc, char const *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap;

    if (argc < 3) {
        cerr << "Использование: " << argv[0] << " <режим> <интерфейс или файл>" << endl << "1 - режим захвата пакетов с сетевого интерфейса\n" << "2 - режим чтение пакетов из pcap файла\n";
        return 1;
    }

    if (strncmp(argv[1], "1", 1) == 0){
        pcap = pcap_open_live(argv[2], BUFSIZ, 1, 1000, errbuf);
        cout << argv[2] << endl;
        if (pcap == NULL) {
            cerr << "Ошибка открытия сетевого интерфейса: " << errbuf << endl;
            return 1;
        }
        cout << "Захват пакетов с сетевого интерфейса " << argv[2] << endl;

    } else if (strncmp(argv[1], "2", 1) == 0){
        pcap = pcap_open_offline(argv[2], errbuf);
        if (pcap == NULL) {
            cerr << "Ошибка открытия файла: " << errbuf << endl;
            return 1;
        }
        cout << "Чтение пакетов из pcap файла " << argv[2] << endl;

    } else{
        cerr << "Неверный режим" << endl << "1 - режим захвата пакетов с сетевого интерфейса\n" << "2 - режим чтение пакетов из pcap файла\n";
        return 1;
    }

    pcap_loop(pcap, 0, packetHandler, NULL);

    pcap_close(pcap);
    return 0;
}