#include "genelBasliklar.h"
#include "ekranTemizleme.h"

pcap_if_t *arayuzSec(void)
{
    pcap_if_t *tumCihazlar;
    pcap_if_t *cihaz = NULL;

    char *hata = malloc(sizeof *hata * PCAP_ERRBUF_SIZE);

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &tumCihazlar, hata) == -1)
    {
        fprintf(stderr, "Cihazlari bulmada hata oldu :=: %s\n", hata);
        pcap_freealldevs(tumCihazlar);
        BIRAK(hata);
        cihaz = NULL;
        ekranTemizleme();
        return cihaz;
    };

    int sayi;
    int sirasi = 0;
    short int devam = 2;
    char girilenSayi[32];
    do
    {
        devam = 2;
        sirasi = 0;
        for (cihaz = tumCihazlar; cihaz != NULL; cihaz = cihaz->next)
        {
            printf("%d. %s", ++sirasi, cihaz->name);
            if (cihaz->description) printf(" (%s)\n", cihaz->description);
            else    printf(" (Cihaz aciklamasi mevcut degil!)\n");
        };
        if (sirasi == 0)
        {
            printf("\nHic Arayuz bulunamadi. NPCAP'i yuklemeyi unutmayin.\n");
            pcap_freealldevs(tumCihazlar);
            BIRAK(hata);
            cihaz = NULL;
            ekranTemizleme();
            return cihaz;
        };

        do{
            printf("\n\tGozetlemek istediginiz arayuzun belirtecini giriniz. (1-%d arasinda) :=: ", sirasi);
            if (fgets(girilenSayi, sizeof girilenSayi, stdin) != 0)
            {
                if (sscanf(girilenSayi, "%d", &sayi) == 1)
                {
                    if (sayi < sirasi + 1 && sayi > 0)  devam = 0;
                    else    break;
                }   else    break; 
            }   else    fprintf(stderr, "fgets hatasi -> Cihaz secme kismindaki.");
        } while (devam > 0);
        ekranTemizleme();
    } while (devam > 0);

    for (cihaz = tumCihazlar, sirasi = 0; sirasi < sayi - 1; cihaz = cihaz->next, sirasi++);

    pcap_freealldevs(tumCihazlar);
    BIRAK(hata);
    ekranTemizleme();
    return cihaz;
};