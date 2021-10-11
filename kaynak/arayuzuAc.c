#include "genelBasliklar.h"
#include "arayuzuAc.h"

void arayuzuAc(pcap_if_t cihaz)
{
    char *hata = malloc(sizeof *hata * PCAP_ERRBUF_SIZE);
    pcap_t *arayuzKullan;
    if ((arayuzKullan = pcap_open(cihaz.name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, hata)) == NULL)
    {
        fprintf(stderr, "\nArayuz acma basarili olmadi. %s Npcap tarafindan desteklenmiyor.", hata);
        BIRAK(hata);
    };
    
    if (cihaz.description)  printf("\n%s arayuzu dinleniyor...\n", cihaz.description);
    else    fprintf(stderr, "\nAciklama yok!");

    //pcap_loop(arayuzKullan, 0, paketYakalama, NULL);

    paketYakalama(arayuzKullan);

    BIRAK(hata);
};