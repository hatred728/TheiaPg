#pragma once

#include "LinkHeader.h"

#define COMPLETE_SIGNATURE_TMDB 0xbd3491fdI32

#define COMPLETE_SIGNATURE_TC 0x1299ece2I32

extern VOID InitTheiaMetaDataBlock(IN OUT PTHEIA_METADATA_BLOCK pTheiaMetaDataBlock);

extern VOID InitTheiaContext(VOID);

extern VOID CheckStatusTheiaCtx(VOID);
