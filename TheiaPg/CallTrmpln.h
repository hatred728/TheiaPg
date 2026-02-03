#pragma once

#include "LinkHeader.h"

typedef struct _ICT_DATA_RELATED
{
    PVOID   pHookRoutine;
    PVOID   pBasePatch;
    PVOID   pHandlerHook;
    ULONG64 LengthHandler;
    UCHAR   LengthAlignment;

}ICT_DATA_RELATED, * PICT_DATA_RELATED;

extern VOID InitCallTrmpln(IN PICT_DATA_RELATED pRelatedDataICT);
