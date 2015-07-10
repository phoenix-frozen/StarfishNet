#ifndef STARFISHNET_DISCOVERY_H
#define STARFISHNET_DISCOVERY_H

#include "net/linkaddr.h"
#include "sys/process.h"

PROCESS_NAME(starfishnet_discovery_process);

void SN_Beacon_input();
void SN_Beacon_update();
void SN_Beacon_TX();

int8_t SN_Discover_neighbors();

#endif //STARFISHNET_DISCOVERY_H
