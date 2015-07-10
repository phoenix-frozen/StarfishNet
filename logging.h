#ifndef __SN_LOGGING_H__
#define __SN_LOGGING_H__

/* If debugging is turned on, set a default debug level.
 */
#ifdef SN_DEBUG
#ifndef SN_DEBUG_LEVEL
#define SN_DEBUG_LEVEL 3
#endif //SN_DEBUG_LEVEL
#endif //SN_DEBUG

#ifdef SN_DEBUG
#ifndef __FUNCTION__
#define __FUNCTION__ __func__
#endif //__FUNCTION__

#ifndef PRIx32
#define PRIx32 "lx"
#endif //PRIx32

#include <stdio.h>
#include "sys/clock.h"
#include "cc253x.h"
#define SN_Printf(level, fmt, x...) printf("[T=% 6u](SP=0x%02x) SN_" level " %s: " fmt, clock_time(), SP, __FUNCTION__, ##x)
#else /* SN_DEBUG */
#define SN_Printf(x...)
#endif /* SN_DEBUG */

#if (SN_DEBUG_LEVEL > 0)
#define SN_ErrPrintf(fmt, x...) SN_Printf("ERROR", fmt, ##x)
#else //0
#define SN_ErrPrintf(x...)
#endif //0

#if (SN_DEBUG_LEVEL > 1)
#define SN_WarnPrintf(fmt, x...) SN_Printf("WARN ", fmt, ##x)
#else //1
#define SN_WarnPrintf(x...)
#endif //1

#if (SN_DEBUG_LEVEL > 2)
#define SN_InfoPrintf(fmt, x...) SN_Printf("INFO ", fmt, ##x)
#else //2
#define SN_InfoPrintf(x...)
#endif //2

#if (SN_DEBUG_LEVEL > 3)
#define SN_DebugPrintf(fmt, x...) SN_Printf("DEBUG", fmt, ##x)
#else //3
#define SN_DebugPrintf(x...)
#endif //3

#endif /* __SN_LOGGING_H__ */
