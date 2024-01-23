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
    cout << argv[1] << endl;

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
        cout << "Захват пакетов с сетевого интерфейса" << argv[2] << endl;

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