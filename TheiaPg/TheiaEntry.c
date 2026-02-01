#include "LinkHeader.h"
  
/**
* Routine: TheiaEntry
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param NoParams
*
* Description: TheiaEntry routine.
*/
VOID TheiaEntry(VOID)
{
    #define ERROR_THEIA_ENTRY 0xd1baa81aUI32

    CONST UCHAR RetOpcode = 0xC3UI8;
  
    CONST UCHAR StopSig[3] = { 0xCC,0xCC,0xCC };

    ICT_DATA_RELATED RelatedDataICT = { 0 };

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    InitTheiaContext();

    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiMcaDeferredRecoveryService;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiMcaDeferredRecoveryService\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pFsRtlUninitializeSmallMcb;

    DbgLog("[TheiaPg <+>] TheiaEntry: FixFsRtlUninitializeSmallMcb\n");

    HrdIndpnRWVMemory(&DataIndpnRWVMem);

    DataIndpnRWVMem.pVa = g_pTheiaCtx->pFsRtlTruncateSmallMcb;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixFsRtlTruncateSmallMcb\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiDecodeMcaFault;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiDecodeMcaFault\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pCcBcbProfiler;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixCcBcbProfiler\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pCcBcbProfiler2;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixCcBcbProfiler2\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiDispatchCallout;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiDispatchCallout\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiSwInterruptDispatch;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiSwInterruptDispatch\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixgMaxDataSize\n");
    
    //
    // Nulling gMaxDataSize is necessary to neutralize the PG check routine,
    // which is called through a global pointer in the kernel module mssecflt.sys and checks MaxDataSize is NULL, if NULL is detected
    // then the execution of the check routine logically jump to epilog, unlike KiSwInterruptDispatch.
    //
    *(PULONG64)g_pTheiaCtx->ppMaxDataSize = NULL; ///< pp: pointer to pointer.
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixPgPrcbFields\n");
    
    g_pTheiaCtx->pKeIpiGenericCall(&SearchKdpcInPgPrcbFields, NULL);

    DbgLog("[TheiaPg <+>] TheiaEntry: FixgKiBalanceSetManagerPeriodicDpc\n");

    if (((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine != g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine)
    {
        DbgLog("[TheiaPg <+>] TheiaEntry: Detect PG-DeferredRoutine in gKiBalanceSetManagerPeriodicDpc | DeferredRoutine: 0x%I64X\n", ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine);

        DataIndpnRWVMem.pVa = ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine;

        HrdIndpnRWVMemory(&DataIndpnRWVMem);

        ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine = g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine;
    }
    else if ((((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredContext != g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent))
    {
        //
        // If the DeferredContext field represents a value that does not have a canonical part inherent to VA-UserSpace/KernelSpace, 
        // then KiCustomAccessRoutineX from __try (SEH) is called:
        // ###
        // 
        // LONG __fastcall KiBalanceSetManagerDeferredRoutine(PKDPC pDpc (RCX), PKEVENT DeferredContext (RDX), PVOID SystemArgument1 (R8), PVOID SystemArgument2 (R9))
        // {
        //     _DWORD v9[22]; // [rsp+0h] [rbp-158h] BYREF
        //     _BYTE v10[55]; // [rsp+90h] [rbp-C8h] BYREF
        //     __int64 v11; // [rsp+C7h] [rbp-91h]
        //     __int64 v12; // [rsp+E7h] [rbp-71h]
        //     _DWORD* v13; // [rsp+140h] [rbp-18h]
        // 
        //     v13 = v9;
        //     memset_0(v10, 0, 0x5Fu);
        // 
        //     ##
        //     ## It is the high-entropy encrypted BaseVa-PgCtx passed via DeferredContext that will cause an exception in the __unwind block later in the recursive call loop of one of the KiCustomRecurseRoutineX.
        //     ##
        //     if ((__int64)DeferredContext >> 47 != 0xff && (__int64)DeferredContext >> 47 != 0x00) ###< Checking the canonical part (VA-KernelSpace/UserSpace) of the DeferredContext value.
        //     {
        //         v9[12] = 0;
        //         *(_BYTE*)pDpc = 0;
        //         *(_QWORD*)(pDpc + 32) = SystemArgument2 >> 8;
        //         v12 = SystemArgument1;
        //         v11 = __ROL8__(DeferredContext, SystemArgument1);
        //         *(_QWORD*)&v10[31] = __ROR8__(pDpc, SystemArgument1);
        //         *(_QWORD*)(a1 + 40) ^= SystemArgument2;
        //         *(_QWORD*)(a1 + 48) ^= SystemArgument1;
        //         KiCustomAccessRoutine6(DeferredContext); ###< Call the caller KiCustomRecurseRoutineX.
        //     }
        // 
        //     return KeSetEvent(DeferredContext, 10, 0);
        // }
        // 
        // ###
        // This means that PgInitRoutine may not overwrite the DeferredRoutine field with one of the PgDpcRoutines instead,
        // the DeferredContext field may be passed an encrypted BaseVa-PgCtx that initiates the launch of the check procedures.
        //
        DbgLog("[TheiaPg <+>] TheiaEntry: Detect PG-DeferredContext in gKiBalanceSetManagerPeriodicDpc | DeferredContext: 0x%I64X\n", ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredContext);

        ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredContext = g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent;
    }
    else { VOID; } ///< For clarity.

    RelatedDataICT.pHookRoutine = &VsrKiExecuteAllDpcs;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiExecuteAllDpcs, g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrKiExecuteAllDpcs not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_HOOK_ALIGNMENT;
    
    HkInitCallTrmpln(&RelatedDataICT);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiExecuteAllDpcs is init\n");
    
    RelatedDataICT.pHookRoutine = &VsrKiRetireDpcList;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiRetireDpcList, g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrKiRetireDpcList not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_HOOK_ALIGNMENT;
    
    HkInitCallTrmpln(&RelatedDataICT);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiRetireDpcList is init\n");

    RelatedDataICT.pHookRoutine = &VsrKiDeliverApc;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiDeliverApc, g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_MASK, &StopSig, sizeof StopSig);

    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrKiDeliverApc not found\n");

        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }

    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_HOOK_ALIGNMENT;

    HkInitCallTrmpln(&RelatedDataICT);

    DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiDeliverApc is init\n");

    RelatedDataICT.pHookRoutine = &VsrExQueueWorkItem;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pExQueueWorkItem, g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_SIG, g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_MASK, &StopSig, sizeof StopSig);

    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrExQueueWorkItem not found\n");

        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }

    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_HOOK_ALIGNMENT;

    HkInitCallTrmpln(&RelatedDataICT);

    DbgLog("[TheiaPg <+>] TheiaEntry: VsrExQueueWorkItem is init\n");

    RelatedDataICT.pHookRoutine = &VsrExAllocatePool2; 
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pExAllocatePool2, g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_SIG, g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrExAllocatePool2 not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_HOOK_ALIGNMENT;
    
    HkInitCallTrmpln(&RelatedDataICT);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: VsrExAllocatePool2 is init\n");
    
    do
    {
        LONG32 SaveRel32Offset = 0I32;
    
        PVOID pCurrentRecurseRoutine = NULL;
    
        for (BOOLEAN i = FALSE; ; )
        {
            if (!i)
            {
                i = TRUE;
    
                RelatedDataICT.pHookRoutine = &VsrKiCustomRecurseRoutineX;
                RelatedDataICT.pBasePatch = g_pTheiaCtx->pKiCustomRecurseRoutineX;
                RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_HANDLER;
                RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_LEN_HANDLER;
                RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_HOOK_ALIGNMENT;
    
                pCurrentRecurseRoutine = g_pTheiaCtx->pKiCustomRecurseRoutineX;
    
                SaveRel32Offset = *(PLONG32)((PUCHAR)pCurrentRecurseRoutine + 5);
    
                pCurrentRecurseRoutine = (PVOID)(((ULONG64)pCurrentRecurseRoutine + 9) + ((SaveRel32Offset < 0I32) ? ((ULONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (ULONG64)SaveRel32Offset));
            }
            else
            {
                if (pCurrentRecurseRoutine == ((PUCHAR)g_pTheiaCtx->pKiCustomRecurseRoutineX - 4)) { break; }
    
                RelatedDataICT.pBasePatch = ((PUCHAR)pCurrentRecurseRoutine + 4);
    
                SaveRel32Offset = *(PLONG32)((PUCHAR)pCurrentRecurseRoutine + 9);
    
                pCurrentRecurseRoutine = (PVOID)(((ULONG64)pCurrentRecurseRoutine + 13) + ((SaveRel32Offset < 0I32) ? ((ULONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (ULONG64)SaveRel32Offset));
            }
    
            HkInitCallTrmpln(&RelatedDataICT);
        };
    
        DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiCustomRecurseRoutineX is init\n\n");
    
    } while (FALSE);

    InitSearchPgSysThread();

    return;
}
