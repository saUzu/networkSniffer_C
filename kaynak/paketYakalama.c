#include "genelBasliklar.h"
#include "basliklar.h"

void paketIsle(const u_char *, int);

void veridenDosyaya(u_char *, int, FILE *);
void eternettenDosyaya(const u_char *, FILE *);
void ipdenDosyaya(const u_char *, int, FILE *);
void tcpDenDosyaya(const u_char *, int);
void udpDenDosyaya(const u_char *, int);
void icmpDenDosyaya(const u_char *, int);

FILE *tcpKayitDosyasi;
FILE *udpKayitDosyasi;
FILE *icmpKayitDosyasi;
unsigned int tcp = 0, udp = 0, icmp = 0, diger = 0, igmp = 0, toplam = 0, s1, s2;
struct sockaddr_in kaynak, hedef;
char hex[2];
eternetBasligi *ethBasligi;
ipBasligi *ipV4Basligi;
tcpBasligi *tBasligi;
udpBasligi *uBasligi;
icmpBasligi *iBasligi;
const u_char *veri;


void paketYakalama(pcap_t *arayuzKullan)
{
    fopen_s(&tcpKayitDosyasi, "tcpKayitDosyasi.txt", "w");
    fopen_s(&udpKayitDosyasi, "udpKayitDosyasi.txt", "w");
    fopen_s(&icmpKayitDosyasi, "icmpKayitDosyasi.txt", "w");
    u_int oku;
    const u_char *paketVerisi;
    struct pcap_pkthdr *baslik;
    time_t saniye;
    struct tm zArasi;
    char buffer[100];

    //fprintf(stderr, "\n\nPaket yakalama! ODU BEE\n\n");

    while ((oku = pcap_next_ex(arayuzKullan, &baslik, &paketVerisi)) >= 0)
    {
        if(oku==0)  continue;
        saniye = baslik->ts.tv_sec;
        localtime_s(&zArasi, &saniye);
        strftime(buffer, 80, "%d-%b-%Y %I:%M:%S %p", &zArasi);
        //printf("\nSiradaki Paket : %s.%ld (Paket Uzunlugu : %d byte) ", buffer, baslik->ts.tv_usec, baslik->len);
        paketIsle(paketVerisi, baslik->caplen);
        //fprintf(stderr, "\n\nPaket yakalama! while ici calisti\n\n");
        //break;
    };
};

void paketIsle(const u_char *paketVerisi, int boyut)
{
    ethBasligi = (eternetBasligi *)paketVerisi;
    ++toplam;

    //fprintf(stderr, "\n\nPaket islenin ici\n\n");

    if (ntohs(ethBasligi->tur) == 0x0800)
    {
        ipV4Basligi = (ipBasligi *)(paketVerisi + sizeof(eternetBasligi));

        switch (ipV4Basligi->protokol)
        {
        case 1:     //  ICMP Protokolü belirteci. ping paket protokolü
            icmp++;
            icmpDenDosyaya(paketVerisi, boyut);
            break;
        case 2:     //  IGMP Protokolü belirteci. genel yayın protokolü
            igmp++;
            //  yazdırma
            break;
        case 6:     //  TCP Protokolü belirteci.
            tcp++;
            tcpDenDosyaya(paketVerisi, boyut);
            break;
        case 17:    //  UDP Protokolü belirteci
            udp++;
            udpDenDosyaya(paketVerisi, boyut);
            break;

        default:
            diger++;
            break;
        };
    };
    printf("\rTCP : %d | UDP : %d | ICMP : %d | IGMP : %d | Diger : %d | Toplam : %d", tcp, udp, icmp, igmp, diger, toplam);
};

void eternettenDosyaya(const u_char *paketVerisi, FILE *dosya)
{
    eternetBasligi *eth = (eternetBasligi *)paketVerisi;
    fflush(stdout);
    fprintf(dosya, "\n");
    fprintf(dosya, "\t\t\tETHERNET BASLIGI\n");
    fprintf(dosya, " | -Hedef Adresi\t\t:\t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->hedef[0], eth->hedef[1], eth->hedef[2], eth->hedef[3], eth->hedef[4], eth->hedef[5]);
    fprintf(dosya, " | -Kaynak Adresi\t\t:\t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->kaynak[0], eth->kaynak[1], eth->kaynak[2], eth->kaynak[3], eth->kaynak[4], eth->kaynak[5]);
    fprintf(dosya, " | -Protokol\t\t\t:\t0x%.4x \n",ntohs(eth->tur));
};

void ipdenDosyaya(const u_char *paketVerisi, int boyut, FILE *dosya)
{
    ipV4Basligi = (ipBasligi *)(paketVerisi + sizeof(eternetBasligi));

    memset(&kaynak, 0, sizeof(kaynak));
    kaynak.sin_addr.S_un.S_addr = ipV4Basligi->kaynak;

    memset(&hedef, 0, sizeof(hedef));
    hedef.sin_addr.S_un.S_addr = ipV4Basligi->hedef;

    eternettenDosyaya(paketVerisi, dosya);

    fflush(stdout);
    fprintf(dosya, "\n");
    fprintf(dosya, "\t\t\tIP BASLIGI\n");
    fprintf(dosya, " | -IP Surumu\t\t\t:\t%d\n", (unsigned int)ipV4Basligi->surum);
    fprintf(dosya, " | -IP Baslik Boyutu\t\t:\t%d DWORD yada %d SA(Byte)\n", (unsigned int)ipV4Basligi->ipBaslikUzunlugu, ((unsigned int)(ipV4Basligi->ipBaslikUzunlugu)) * 4);
    fprintf(dosya, " | -Hizmet Turu\t\t\t:\t%d\n", (unsigned int)ipV4Basligi->hizmetTuru);
    fprintf(dosya, " | -IP Basliginin Toplam Boyutu\t:\t%d SA(Byte)\n", ntohs(ipV4Basligi->toplamUzunluk));
    fprintf(dosya, " | -IP Tanimi\t\t\t:\t%d\n", ntohs(ipV4Basligi->tanimlama));
    fprintf(dosya, " | -'Ayrilmis Sifir' Alani\t:\t%d\n", (unsigned int)ipV4Basligi->ayrilmisParcasi);
    fprintf(dosya, " | -'Asla' Alani\t\t:\t%d\n", (unsigned int)ipV4Basligi->aslaParcasi);
    fprintf(dosya, " | -'Fazlalik' Alani\t\t:\t%d\n", (unsigned int)ipV4Basligi->fazlalikParcasi);
    fprintf(dosya, " | -Atlama Sayisi(TTL)\t\t:\t%d\n", (unsigned int)ipV4Basligi->yasamSuresi);
    fprintf(dosya, " | -Protokol\t\t\t:\t%d\n", (unsigned int)ipV4Basligi->protokol);
    fprintf(dosya, " | -Baslik Saglama\t\t:\t%d\n", (unsigned int)ipV4Basligi->baslikSaglama);
    fprintf(dosya, " | -Kaynak Adresi\t\t:\t%s\n", inet_ntoa(kaynak.sin_addr));
    fprintf(dosya, " | -Hedef Adresi\t\t:\t%s\n", inet_ntoa(hedef.sin_addr));
};

void tcpDenDosyaya(const u_char *paketVerisi, int boyut)
{
    unsigned short ipBaslikBoyutu;
    int tcpBaslikBoyutu, veriBoyutu;

    ipV4Basligi = (ipBasligi *)(paketVerisi + sizeof(eternetBasligi));
    ipBaslikBoyutu = ipV4Basligi->ipBaslikUzunlugu * 4;

    tBasligi = (tcpBasligi *)(paketVerisi + sizeof(eternetBasligi));
    tcpBaslikBoyutu = tBasligi->secenekler * 4;

    veri = (paketVerisi + sizeof(eternetBasligi) + ipBaslikBoyutu + tcpBaslikBoyutu);
    veriBoyutu = (boyut - sizeof(eternetBasligi) - ipBaslikBoyutu - tcpBaslikBoyutu);

    fflush(stdout);
    fprintf(tcpKayitDosyasi, "\n\n*******************************TCP PAKETI*******************************\n");
    ipdenDosyaya(paketVerisi, boyut, tcpKayitDosyasi);
    fflush(stdout);
    fprintf(tcpKayitDosyasi, "\n");
    fprintf(tcpKayitDosyasi, "\t\t\tTCP BASLIGI\n");
    fprintf(tcpKayitDosyasi, " | -Kaynak Port\t\t\t:\t%u\n", ntohs(tBasligi->kaynakPort));
    fprintf(tcpKayitDosyasi, " | -Hedef Port\t\t\t:\t%u\n", ntohs(tBasligi->hedefPort));
    fprintf(tcpKayitDosyasi, " | -Sira Sayisi\t\t\t:\t%lu\n", ntohl(tBasligi->sira));
    fprintf(tcpKayitDosyasi, " | -Onay Sayisi\t\t\t:\t%lu\n", ntohl(tBasligi->onay));
    fprintf(tcpKayitDosyasi, " | -Baslik Boyutu\t\t:\t%d DWORDS or %d SA(Byte)\n", (unsigned int)tBasligi->secenekler, (unsigned int)tBasligi->secenekler * 4);
    fprintf(tcpKayitDosyasi, " | -CWR Bayragi\t\t\t:\t%d\n", (unsigned int)tBasligi->cwr);
    fprintf(tcpKayitDosyasi, " | -ECN Bayragi\t\t\t:\t%d\n", (unsigned int)tBasligi->ecn);
    fprintf(tcpKayitDosyasi, " | -Urgent Bayragi\t\t:\t%d\n", (unsigned int)tBasligi->urg);
    fprintf(tcpKayitDosyasi, " | -Acknowledgement Bayragi\t:\t%d\n", (unsigned int)tBasligi->ack);
    fprintf(tcpKayitDosyasi, " | -Push Bayragi\t\t:\t%d\n", (unsigned int)tBasligi->psh);
    fprintf(tcpKayitDosyasi, " | -Reset Bayragi\t\t:\t%d\n", (unsigned int)tBasligi->rst);
    fprintf(tcpKayitDosyasi, " | -Synchronise Bayragi\t\t:\t%d\n", (unsigned int)tBasligi->syn);
    fprintf(tcpKayitDosyasi, " | -Finish Bayragi\t\t:\t%d\n", (unsigned int)tBasligi->fin);
    fprintf(tcpKayitDosyasi, " | -Pencere\t\t\t:\t%d\n", ntohs(tBasligi->pencere));
    fprintf(tcpKayitDosyasi, " | -Saglama\t\t\t:\t%d\n", ntohs(tBasligi->saglama));
    fprintf(tcpKayitDosyasi, " | -Acil Isaretcisi\t\t:\t%d\n", tBasligi->acil);
    fprintf(tcpKayitDosyasi, "\n\t\t\tVeri\t\n");

    fprintf(tcpKayitDosyasi, " \tIP Basligi\n");
    veridenDosyaya((u_char *)ipV4Basligi, ipBaslikBoyutu, tcpKayitDosyasi);
    fflush(stdout);
    fprintf(tcpKayitDosyasi, " \tTCP Basligi\n");
    veridenDosyaya((u_char *)tBasligi, tcpBaslikBoyutu, tcpKayitDosyasi);
    fflush(stdout);
    fprintf(tcpKayitDosyasi, " \tVeri Yuku\n");
    veridenDosyaya((u_char *)veri, veriBoyutu, tcpKayitDosyasi);
};

void udpDenDosyaya(const u_char *paketVerisi, int boyut)
{
    int ipBaslikBoyutu, veriBoyutu;

    ipV4Basligi = (ipBasligi *)(paketVerisi + sizeof(eternetBasligi));
    ipBaslikBoyutu = ipV4Basligi->ipBaslikUzunlugu * 4;
    uBasligi = (udpBasligi *)(paketVerisi + ipBaslikBoyutu + sizeof(eternetBasligi));
    veri = (paketVerisi + sizeof(eternetBasligi) + ipBaslikBoyutu + sizeof(udpBasligi));
    veriBoyutu = (boyut - sizeof(eternetBasligi) - ipBaslikBoyutu - sizeof(udpBasligi));

    fflush(stdout);
    fprintf(udpKayitDosyasi, "\n\n*******************************UDP PAKETI*******************************\n");
    ipdenDosyaya(paketVerisi, boyut, udpKayitDosyasi);
    fflush(stdout);
    fprintf(udpKayitDosyasi, "\n");
    fprintf(udpKayitDosyasi, "\t\t\tUDP BASLIGI\n");
    fprintf(udpKayitDosyasi, " | -Kaynak Port\t\t\t:\t%u\n", ntohs(uBasligi->kaynakPort));
    fprintf(udpKayitDosyasi, " | -Hedef Port\t\t\t:\t%u\n", ntohs(uBasligi->hedefPort));
    fprintf(udpKayitDosyasi, " | -UDP Boyutu\t\t\t:\t%d\n", ntohs(uBasligi->uzunluk));
    fprintf(udpKayitDosyasi, " | -UDP Saglama\t\t\t:\t%d\n", ntohs(uBasligi->saglama));

    fprintf(udpKayitDosyasi, "\n\t\t\tVeri\t\n");

    fprintf(udpKayitDosyasi, " \tIP Basligi\n");
    veridenDosyaya((u_char *)ipV4Basligi, ipBaslikBoyutu, udpKayitDosyasi);
    fflush(stdout);
    fprintf(udpKayitDosyasi, " \tTCP Basligi\n");
    veridenDosyaya((u_char *)uBasligi, sizeof(udpBasligi), udpKayitDosyasi);
    fflush(stdout);
    fprintf(udpKayitDosyasi, " \tVeri Yuku\n");
    veridenDosyaya((u_char *)veri, veriBoyutu, udpKayitDosyasi);
};

void icmpDenDosyaya(const u_char *paketVerisi, int boyut)
{
    int ipBaslikBoyutu, veriBoyutu;

    ipV4Basligi = (ipBasligi *)(paketVerisi + sizeof(eternetBasligi));
    ipBaslikBoyutu = ipV4Basligi->ipBaslikUzunlugu * 4;
    iBasligi = (icmpBasligi *)(paketVerisi + ipBaslikBoyutu + sizeof(eternetBasligi));
    veri = (paketVerisi + sizeof(eternetBasligi) + ipBaslikBoyutu + sizeof(udpBasligi));
    veriBoyutu = (boyut - sizeof(eternetBasligi) - ipBaslikBoyutu - sizeof(udpBasligi));

    fflush(stdout);
    fprintf(icmpKayitDosyasi, "\n\n*******************************ICMP PAKETI*******************************\n");
    ipdenDosyaya(paketVerisi, boyut, icmpKayitDosyasi);
    fflush(stdout);
    fprintf(icmpKayitDosyasi, "\n");
    fprintf(icmpKayitDosyasi, "\t\t\tICMP BASLIGI\n");
    fprintf(icmpKayitDosyasi, " | -Turu\t\t\t:\t%d\n", (unsigned int)(iBasligi->tur));

    if((unsigned int)(iBasligi->tur)==11)   fprintf(icmpKayitDosyasi, " (Atalama Sayaci hatasi!(TTL))\n");
    else if ((unsigned int)(iBasligi->tur) == 0)    fprintf(icmpKayitDosyasi, " (ICMP Cevap Paketi)\n");

    fprintf(icmpKayitDosyasi, " | -Kod\t\t\t\t:\t%u\n", (unsigned int)(iBasligi->kod));
    fprintf(icmpKayitDosyasi, " | -Saglama\t\t\t:\t%d\n", ntohs(iBasligi->saglama));
    fprintf(icmpKayitDosyasi, " | -Tanim\t\t\t:\t%d\n", ntohs(iBasligi->tanimlama));
    fprintf(icmpKayitDosyasi, " | -Sira\t\t\t:\t%d\n", ntohs(iBasligi->sira));

    fprintf(icmpKayitDosyasi, "\n\t\t\tVeri\t\n");

    fprintf(icmpKayitDosyasi, " \tIP Basligi\n");
    veridenDosyaya((u_char *)ipV4Basligi, ipBaslikBoyutu, icmpKayitDosyasi);
    fflush(stdout);
    fprintf(icmpKayitDosyasi, " \tTCP Basligi\n");
    veridenDosyaya((u_char *)iBasligi, sizeof(icmpBasligi), icmpKayitDosyasi);
    fflush(stdout);
    fprintf(icmpKayitDosyasi, " \tVeri Yuku\n");
    veridenDosyaya((u_char *)veri, veriBoyutu, icmpKayitDosyasi);
};

void veridenDosyaya(u_char *veri, int boyut, FILE *dosya)
{
    unsigned char x, y, satir[17];
    int i, j;
    fflush(stdout);
    for (i = 0; i < boyut; i++)
    {
        y = satir[i];
        fprintf(dosya, " %.2x", (unsigned int)y);
        x = (y >= 32 && y <= 128) ? (unsigned char)y : '.';
        satir[i % 16] = x;
        if ((i != 0 && (i + 1) % 16 == 0) || i == boyut - 1)
        {
            satir[i % 16 + 1] = '\0';
            fprintf(dosya, "          ");

            for (j = strlen((const char *)satir); j < 16; j++)
            {
                fprintf(dosya, "   ");
            };
            fprintf(dosya, "%s\n", satir);
        };
    };
    fprintf(dosya, "\n");
};