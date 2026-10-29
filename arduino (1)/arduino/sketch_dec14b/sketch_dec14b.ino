#include <esp_now.h>
#include <WiFi.h>

uint8_t receiverMac[] = {0xF4, 0x65, 0x0B, 0xE6, 0x81, 0x78};

const char key = 'K';

typedef struct {
  int id;
  unsigned long sendTime;
  char msg[64];
} Packet;

Packet packet;

void xorCrypt(char *text) {
  for (int i = 0; text[i] != '\0'; i++) {
    text[i] = text[i] ^ key;
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);

  if (esp_now_init() != ESP_OK) {
    Serial.println("Erreur ESP-NOW");
    return;
  }

  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, receiverMac, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;

  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("Erreur ajout peer");
    return;
  }

  Serial.println("ESP32-1 Sender pret");
}

void loop() {
  static int id = 1;

  sprintf(packet.msg, "Temp=25.4;Hum=60;ID=%d", id);
  packet.id = id;
  packet.sendTime = millis();

  unsigned long t1 = micros();
  xorCrypt(packet.msg);
  unsigned long encryptTime = micros() - t1;

  esp_now_send(receiverMac, (uint8_t *)&packet, sizeof(packet));

  Serial.print("Envoye ID=");
  Serial.print(id);
  Serial.print(" encrypt_us=");
  Serial.println(encryptTime);

  id++;
  delay(1000);
}