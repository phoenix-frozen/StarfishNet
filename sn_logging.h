#ifndef __SN_LOGGING_H__
#define __SN_LOGGING_H__

#define SN_ErrPrintf(x...)
#define SN_WarnPrintf(x...)
#define SN_InfoPrintf(x...)

#ifdef SN_DEBUG

#include <stdio.h>

#ifndef SN_DEBUG_LEVEL
#define SN_DEBUG_LEVEL 3
#endif //SN_DEBUG_LEVEL

#if (SN_DEBUG_LEVEL > 0)
#undef SN_ErrPrintf
#define SN_ErrPrintf(x...) printf(x)
#endif //0

#if (SN_DEBUG_LEVEL > 1)
#undef SN_WarnPrintf
#define SN_WarnPrintf(x...) printf(x)
#endif //1

#if (SN_DEBUG_LEVEL > 2)
#undef SN_InfoPrintf
#define SN_InfoPrintf(x...) printf(x)
#endif //2

#endif //SN_DEBUG

#endif /* __SN_LOGGING_H__ */

