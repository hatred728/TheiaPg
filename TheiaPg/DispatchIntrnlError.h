#pragma once

#include "LinkHeader.h"

extern volatile BOOLEAN g_DieDeadlockMethod;

extern volatile PVOID g_pDieIndirectCallBugCheck;

extern volatile PVOID g_DieNtosHeadThreadList;

extern volatile PVOID g_DieNonLargePage;

extern DECLSPEC_NORETURN VOID DieDispatchIntrnlError(IN ULONG32 InternalCode);
