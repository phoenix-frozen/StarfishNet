#ifndef STARFISHNET_DISCOVERY_H
#define STARFISHNET_DISCOVERY_H

#include "net/linkaddr.h"
#include "sys/process.h"

PROCESS_NAME(starfishnet_discovery_process);

void SN_Beacon_input(void);
void SN_Beacon_update(void);
void SN_Beacon_TX(void);

int SN_Discover_neighbors(void);

#endif //STARFISHNET_DISCOVERY_H
