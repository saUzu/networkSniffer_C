#ifndef IPBASLIGI_H__
#define IPBASLIGI_H__

#include "stdio.h"
#include "winsock2.h"

typedef struct eternetBasligi
{
    UCHAR hedef[6];
    UCHAR kaynak[6];
    USHORT tur;
} eternetBasligi;

typedef struct ipBasligi
{
    unsigned char surum : 4;
    unsigned char ipBaslikUzunlugu : 4;
    unsigned char hizmetTuru;
    unsigned short toplamUzunluk;
    unsigned short tanimlama;

    unsigned char isaret_pd : 5;            //  pd = parça denkleştirme
    unsigned char fazlalikParcasi : 1;
    unsigned char aslaParcasi : 1;
    unsigned char ayrilmisParcasi : 1;
    unsigned char isaret_pd1;

    unsigned char yasamSuresi;
    unsigned char protokol;
    unsigned short baslikSaglama;            // başlık sağlama toplamı
    unsigned int kaynak;
    unsigned int hedef;

} ipBasligi;

typedef struct udpBasligi
{
    unsigned short kaynakPort;
    unsigned short hedefPort;
    unsigned short uzunluk;
    unsigned short saglama;
} udpBasligi;

typedef struct tcpBasligi
{
    unsigned short kaynakPort;
    unsigned short hedefPort;
    unsigned int sira;
    unsigned int onay;

    unsigned char deneysel : 1;     // nonce flag deneyseldir. gelen paketlerdeki zararlı gizlenmeleri engeller.
    unsigned char ayrilmis : 3;
    unsigned char secenekler : 4;

    unsigned char fin : 1; 
    unsigned char syn : 1; 
    unsigned char rst : 1; 
    unsigned char psh : 1; 
    unsigned char ack : 1; 
    unsigned char urg : 1; 

    unsigned char ecn : 1; 
    unsigned char cwr : 1;

    unsigned short pencere;
    unsigned short saglama;
    unsigned short acil;
} tcpBasligi;

typedef struct icmpBasligi
{
    BYTE tur;
    BYTE kod;
    USHORT saglama;
    USHORT tanimlama;
    USHORT sira;
} icmpBasligi;

#endif