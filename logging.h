#ifndef __SN_LOGGING_H__
#define __SN_LOGGING_H__

/* If debugging is turned on, set a default debug level.
 * If it isn't, but a debug level it set, turn it on.
 */
#ifdef SN_DEBUG
#ifndef SN_DEBUG_LEVEL
#define SN_DEBUG_LEVEL 3
#endif //SN_DEBUG_LEVEL
#else //SN_DEBUG
#ifdef SN_DEBUG_LEVEL
#warning "Debugging is turned off, but a debug level is set. Turning debugging on."
#define SN_DEBUG
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

#define SN_ErrPrintf(x...)
#define SN_WarnPrintf(x...)
#define SN_InfoPrintf(x...)
#define SN_DebugPrintf(x...)

#if (SN_DEBUG_LEVEL > 0)
#undef SN_ErrPrintf
#define SN_ErrPrintf(fmt, x...) SN_Printf("ERROR", fmt, ##x)
#endif //0

#if (SN_DEBUG_LEVEL > 1)
#undef SN_WarnPrintf
#define SN_WarnPrintf(fmt, x...) SN_Printf("WARN ", fmt, ##x)
#endif //1

#if (SN_DEBUG_LEVEL > 2)
#undef SN_InfoPrintf
#define SN_InfoPrintf(fmt, x...) SN_Printf("INFO ", fmt, ##x)
#endif //2

#if (SN_DEBUG_LEVEL > 3)
#undef SN_DebugPrintf
#define SN_DebugPrintf(fmt, x...) SN_Printf("DEBUG", fmt, ##x)
#endif //3

#endif /* __SN_LOGGING_H__ */
