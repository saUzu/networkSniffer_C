#include <stdio.h>
#include <winsock2.h>
#include <windows.h>

#include "genelBasliklar.h"

#include "ana.h"  
#include "ekranTemizleme.h"

int main(int argc, char **argv)
{
    pcap_if_t *cihaz = NULL;
    char devamEtsinMi[32];
    char cevap[32];
    short int devam = 1;

    while (devam > 0 && (cihaz = arayuzSec()) == NULL)
    {
        while (devam > 0)
        {
            fprintf(stderr, "\nHata\t:=:\tCihaz degeri 'NULL' dondu. Arayuz bulunamadi.\n");
            printf("Arayuzleri tekrar aramak ister misiniz? ( EVET (E,e), HAYIR (H,h) ) : ");
            if (fgets(cevap, sizeof cevap, stdin) != 0)
            {
                if (sscanf(cevap, "%s", devamEtsinMi) == 1)
                {
                    if (strncmp(devamEtsinMi, "E", sizeof("E")) == 0 || strncmp(devamEtsinMi, "e", sizeof("e")) == 0)
                        break;
                    else if (strncmp(devamEtsinMi, "H", sizeof("H")) == 0 || strncmp(devamEtsinMi, "h", sizeof("h")) == 0)
                        devam = -1;
                }
                else
                    fprintf(stderr, "Hata\t:=:\tsscanf'de hata olustu. (Cihaz aransin mi kismindaki.)\n");
            }
            else
                fprintf(stderr, "fgets hatasi -> cihaz aransin mi?");
            ekranTemizleme();
        };
        ekranTemizleme();
    };
    
    
    arayuzuAc(*cihaz);

    fprintf(stderr, "\nCikis Yapiliyor...\n");
    getchar();
    return 0;
};