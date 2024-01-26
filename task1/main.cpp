// #include <pcap.h>
// #include <iostream>
// #include <cstring>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <netinet/udp.h>
// #include <fstream>
// #include <unordered_map>
// #include <csignal>
// #include <functional>
// #include <atomic>

#include "PacketClassifier.h"

using namespace std;


int main(int argc, char const* argv[]) {
    if (argc < 3) {
        cerr << "Использование: " << argv[0] << " <режим> <интерфейс или файл>" << endl << "1 - режим захвата пакетов с сетевого интерфейса\n" << "2 - режим чтение пакетов из pcap файла\n";
        return 1;
    }

    PacketClassifier* packetClassifierInstance = PacketClassifier::getInstance("output.csv");

    packetClassifierInstance->processPackets(argv[1], argv[2]);

    return 0;
}
