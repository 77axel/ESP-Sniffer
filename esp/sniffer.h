#ifndef SNIFFER_H
#define SNIFFER_H

#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>

#define CHANNEL_HOP_INTERVAL_MS 500
#define MAX_PACKET_SIZE 1600

void sniffer_init();
void sniffer_loop();

#endif