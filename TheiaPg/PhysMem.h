#pragma once

#include "LinkHeader.h"

typedef struct _INDPN_RW_V_MEMORY_DATA
{
	UCHAR FlagsExecute;

	PVOID pVa;

	PVOID pIoBuffer;

	ULONG64 LengthRW;

}INDPN_RW_V_MEMORY_DATA, *PINDPN_RW_V_MEMORY_DATA;

#define MEM_INDPN_RW_READ_OP_BIT   1UI8 // 0-bit

#define MEM_INDPN_RW_WRITE_OP_BIT  2UI8 // 2-bit

extern VOID HrdIndpnRWVMemory(IN OUT PINDPN_RW_V_MEMORY_DATA pInputData);

extern VOID HrdPatchAttributesInputPte(IN ULONG64 AndMask, IN ULONG64 OrMask, IN OUT PVOID pVa);

extern PMMPTE_HARDWARE HrdGetPteInputVa(IN PVOID pVa);
