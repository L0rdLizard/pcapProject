#include <pcap.h>
#include <iostream>

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    // Обработка пакета здесь
    std::cout << "Время получения: " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec << std::endl;

    // Выводим размер пакета
    std::cout << "Размер пакета: " << pkthdr->len << " байт" << std::endl;
}


int main(int argc, char const *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(argv[1], errbuf);

    if (pcap == NULL) {
        std::cerr << "Ошибка открытия файла: " << errbuf << std::endl;
        return 1;
    }

    pcap_loop(pcap, 0, packetHandler, NULL);

    pcap_close(pcap);
    return 0;
}