#include <pcap.h>
#include <iostream>
#include <cstring>

using namespace std;

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    cout << "Время получения: " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec << std::endl;

    cout << "Размер пакета: " << pkthdr->len << " байт" << std::endl;
}


int main(int argc, char const *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap;

    if (argc < 2) {
        cerr << "Использование: " << argv[0] << " <интерфейс или файл>" << endl;
        return 1;
    }

    if (strncmp(argv[1], "eth", 3) == 0 || strncmp(argv[1], "wlan", 4) == 0) {
        pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
            cerr << "Ошибка открытия сетевого интерфейса: " << errbuf << endl;
            return 1;
        }
        cout << "Захват пакетов с сетевого интерфейса\n";

    } else {
        pcap = pcap_open_offline(argv[1], errbuf);
        if (pcap == NULL) {
            cerr << "Ошибка открытия файла: " << errbuf << endl;
            return 1;
        }
        cout << "Чтение пакетов из pcap файла" << argv[1] << endl;
        
    }

    pcap_loop(pcap, 0, packetHandler, NULL);

    pcap_close(pcap);
    return 0;
}