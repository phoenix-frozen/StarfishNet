#ifndef __SN_LOGGING_H__
#define __SN_LOGGING_H__

#ifdef SN_DEBUG
#include <stdio.h>
#define SN_Printf(level, fmt, x...) fprintf(stderr, "SN_" level " %s: " fmt, __FUNCTION__, ##x)
#else /* SN_DEBUG */
#define SN_Printf(x...)
#endif /* SN_DEBUG */

#define SN_ErrPrintf(x...)
#define SN_WarnPrintf(x...)
#define SN_InfoPrintf(x...)
#define SN_DebugPrintf(x...)

#ifndef SN_DEBUG_LEVEL
#define SN_DEBUG_LEVEL 3
#endif //SN_DEBUG_LEVEL

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
