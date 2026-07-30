#include "sniffer.h"
#include <esp_system.h>
#include <nvs_flash.h>
#include <stdio.h>
#include <string.h>
#include "esp_log.h"

static const uint8_t pcap_global_header[24] = {
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed)) pcap_pkthdr_t;

static uint8_t channel = 1;
static unsigned long last_channel_change = 0;

static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t *ctrl = &pkt->rx_ctrl;
    uint8_t *frame = pkt->payload;
    int len = ctrl->sig_len;

    if (len <= 0 || len > MAX_PACKET_SIZE) return;

    pcap_pkthdr_t pkt_hdr;
    pkt_hdr.ts_sec  = ctrl->timestamp / 1000000;
    pkt_hdr.ts_usec = ctrl->timestamp % 1000000;
    pkt_hdr.incl_len = len;
    pkt_hdr.orig_len = len;

    Serial.write((uint8_t *)&pkt_hdr, sizeof(pcap_pkthdr_t));
    Serial.write(frame, len);
}

static void channel_hop() {
    channel = (channel % 13) + 1;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void sniffer_init() {
    esp_log_level_set("*", ESP_LOG_NONE);
    Serial.begin(921600);
    delay(1000);
    nvs_flash_init();
    esp_netif_init();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer_cb);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filter);

    Serial.write(pcap_global_header, 24);
}

void sniffer_loop() {
    if (millis() - last_channel_change > CHANNEL_HOP_INTERVAL_MS) {
        channel_hop();
        last_channel_change = millis();
    }
    delay(10);
}