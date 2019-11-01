/** @file
  This library is BaseCrypto router. It will redirect hash request to each individual
  hash handler registerd, such as SHA1, SHA256, SHA384 and SM3...

Copyright (c) 2013 - 2018, Intel Corporation. All rights reserved. <BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/HashLib.h>
#include <Library/HobLib.h>
#include <Guid/ZeroGuid.h>

#include <Library/BaseHashLib.h>
#include "BaseHashLibCommon.h"

#define BASEHASH_LIB_PEI_ROUTER_GUID \
  { 0x19ea22c7, 0xf870, 0x4b5e, { 0x98, 0x86, 0x9c, 0x29, 0xb2, 0x20, 0xf0, 0x39 } }


EFI_GUID mBaseHashLibPeiRouterGuid = BASEHASH_LIB_PEI_ROUTER_GUID;

typedef struct {
  //
  // If gZeroGuid, SupportedHashMask is 0 for FIRST module which consumes HashLib
  //   or the hash algorithm bitmap of LAST module which consumes HashLib.
  //   HashInterfaceCount and HashInterface are all 0.
  // If gEfiCallerIdGuid, HashInterfaceCount, HashInterface and SupportedHashMask
  //   are the hash interface information of CURRENT module which consumes HashLib.
  //
  EFI_GUID         Identifier;
  UINTN            HashInterfaceCount;
  HASH_INTERFACE_UNIFIED_API HashInterface[HASH_ALGO_COUNT];
  UINT32           SupportedHashMask;
} HASH_INTERFACE_HOB;


UINT32
EFIAPI
GetApiHashMaskFromAlgo (
  IN EFI_GUID  *HashGuid
  )
{
  UINTN  Index;

  for (Index = 0; Index < sizeof(mHashMask)/sizeof(mHashMask[0]); Index++) {
    if (CompareGuid (HashGuid, &mHashMask[Index].Guid)) {
      return mHashMask[Index].Mask;
    }
  }
  return 0;
}

/**
  This function gets hash interface hob.

  @param Identifier    Identifier to get hash interface hob.

  @retval hash interface hob.
**/
HASH_INTERFACE_HOB *
InternalGetBaseHashInterfaceHob (
  EFI_GUID      *Identifier
  )
{
  EFI_PEI_HOB_POINTERS  Hob;
  HASH_INTERFACE_HOB    *HashInterfaceHob;

  Hob.Raw = GetFirstGuidHob (&mBaseHashLibPeiRouterGuid);
  while (Hob.Raw != NULL) {
    HashInterfaceHob = GET_GUID_HOB_DATA (Hob);
    if (CompareGuid (&HashInterfaceHob->Identifier, Identifier)) {
      //
      // Found the matched one.
      //
      return HashInterfaceHob;
    }
    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextGuidHob (&mBaseHashLibPeiRouterGuid, Hob.Raw);
  }

  return NULL;
}

/**
  This function creates hash interface hob.

  @param Identifier    Identifier to create hash interface hob.

  @retval hash interface hob.
**/
HASH_INTERFACE_HOB *
InternalCreateBaseHashInterfaceHob (
  EFI_GUID      *Identifier
  )
{
  HASH_INTERFACE_HOB LocalHashInterfaceHob;

  ZeroMem (&LocalHashInterfaceHob, sizeof(LocalHashInterfaceHob));
  CopyGuid (&LocalHashInterfaceHob.Identifier, Identifier);
  return BuildGuidDataHob (&mBaseHashLibPeiRouterGuid, &LocalHashInterfaceHob, sizeof(LocalHashInterfaceHob));
}

/**
  Init hash sequence.

  @param HashType   Hash Type.
  @param HashHandle Hash handle.

  @retval EFI_SUCCESS          Hash start and HashHandle returned.
  @retval EFI_UNSUPPORTED      System has no HASH library registered.
**/
EFI_STATUS
EFIAPI
HashApiInit (
  IN   UINT32         HashType,
  OUT  HASH_HANDLE   *HashHandle
)
{
  HASH_HANDLE    *HashCtx;
  HASH_INTERFACE_HOB *HashInterfaceHob;
  UINTN   Index;
  UINT32  HashMask;
  UINT32  HashPolicy;

  HashInterfaceHob = InternalGetBaseHashInterfaceHob (&gEfiCallerIdGuid);
  if (HashInterfaceHob == NULL) {
    return EFI_UNSUPPORTED;
  }

  if (HashType != HASH_ALG_DEFAULT){
    HashPolicy = HashType;
    DEBUG ((DEBUG_INFO, "HashApiInit hashpolicy 0x%x\n",HashPolicy));

  } else {
    HashPolicy = PcdGet32 (PcdSystemHashPolicy);
    DEBUG ((DEBUG_INFO, "Default hashpolicy \n"));

  }

  if ((HashInterfaceHob->HashInterfaceCount == 0) || !(HashInterfaceHob->SupportedHashMask & HashPolicy)) {
    DEBUG ((DEBUG_INFO,"Unsupported Hash Type 0x%x \n", HashPolicy));
    return EFI_UNSUPPORTED;
  }

  HashCtx = AllocatePool (sizeof(*HashCtx));
  ASSERT (HashCtx != NULL);

  for (Index = 0; Index < HashInterfaceHob->HashInterfaceCount; Index++) {
    HashMask = GetApiHashMaskFromAlgo (&HashInterfaceHob->HashInterface[Index].HashGuid);
    if ((HashMask & HashPolicy) != 0) {
      HashInterfaceHob->HashInterface[Index].HashInit (HashCtx);
      break;
    }
  }

  // Check for hash type supported
  if(Index == HashInterfaceHob->HashInterfaceCount)
    return EFI_UNSUPPORTED;

  *HashHandle = (HASH_HANDLE)HashCtx;

  return EFI_SUCCESS;
}

/**
  Update hash data.

  @param HashHandle    Hash handle.
  @param HashType   Hash Type.
  @param DataToHash    Data to be hashed.
  @param DataToHashLen Data size.

  @retval EFI_SUCCESS          Hash updated.
  @retval EFI_UNSUPPORTED      System has no HASH library registered.
**/
EFI_STATUS
EFIAPI
HashApiUpdate (
  IN HASH_HANDLE    HashHandle,
  IN UINT32          HashType,
  IN VOID           *DataToHash,
  IN UINTN          DataToHashLen
)
{
  HASH_INTERFACE_HOB *HashInterfaceHob;
  HASH_HANDLE  *HashCtx;
  UINTN        Index;
  UINT32       HashMask;
  UINT32       HashPolicy;

  HashInterfaceHob = InternalGetBaseHashInterfaceHob (&gEfiCallerIdGuid);
  if (HashInterfaceHob == NULL) {
    return EFI_UNSUPPORTED;
  }

  if (HashType != HASH_ALG_DEFAULT){
    HashPolicy = HashType;
  } else {
    HashPolicy = PcdGet32 (PcdSystemHashPolicy);
  }

  if ((HashInterfaceHob->HashInterfaceCount == 0) || !(HashInterfaceHob->SupportedHashMask & HashPolicy)) {
    DEBUG ((DEBUG_INFO,"Unsupported Hash Type 0x%x \n", HashPolicy));
    return EFI_UNSUPPORTED;
  }

  HashCtx = (HASH_HANDLE *)HashHandle;

  for (Index = 0; Index < HashInterfaceHob->HashInterfaceCount; Index++) {
    HashMask = GetApiHashMaskFromAlgo (&HashInterfaceHob->HashInterface[Index].HashGuid);
    if ((HashMask & HashPolicy) != 0) {
      HashInterfaceHob->HashInterface[Index].HashUpdate (HashCtx[0], DataToHash, DataToHashLen);
      break;
    }
  }

    // Check for hash type supported
  if(Index == HashInterfaceHob->HashInterfaceCount) {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

/**
  Hash complete.

  @param HashHandle    Hash handle.
  @param HashType      Hash Type.
  @param Digest        Hash Digest.

  @retval EFI_SUCCESS     Hash complete and Digest is returned.
**/
EFI_STATUS
EFIAPI
HashApiFinal (
  IN  HASH_HANDLE HashHandle,
  IN  UINT32      HashType,
  OUT UINT8      *Digest
)
{
  HASH_INTERFACE_HOB *HashInterfaceHob;
  HASH_HANDLE  *HashCtx;
  UINTN        Index;
  UINT32       HashMask;
  UINT32       HashPolicy;

  HashInterfaceHob = InternalGetBaseHashInterfaceHob (&gEfiCallerIdGuid);
  if (HashInterfaceHob == NULL) {
    return EFI_UNSUPPORTED;
  }

  if (HashType != HASH_ALG_DEFAULT){
    HashPolicy = HashType;
  } else {
    HashPolicy = PcdGet32 (PcdSystemHashPolicy);
  }

  if ((HashInterfaceHob->HashInterfaceCount == 0) || !(HashInterfaceHob->SupportedHashMask & HashPolicy)) {
      DEBUG ((DEBUG_INFO,"Unsupported Hash Type 0x%x \n", HashPolicy));
    return EFI_UNSUPPORTED;
  }

  HashCtx = (HASH_HANDLE *)HashHandle;

  for (Index = 0; Index < HashInterfaceHob->HashInterfaceCount; Index++) {
    HashMask = GetApiHashMaskFromAlgo (&HashInterfaceHob->HashInterface[Index].HashGuid);
    if (HashMask & HashPolicy) {
      HashInterfaceHob->HashInterface[Index].HashFinal (HashCtx[0], &Digest);
      break;
    }
  }

  // Check for hash type supported
  if(Index == HashInterfaceHob->HashInterfaceCount){
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

/**
  This service registers Hash Interface.

  @param HashInterface  Hash interface

  @retval EFI_SUCCESS          This hash interface is registered successfully.
  @retval EFI_UNSUPPORTED      System does not support register this interface.
  @retval EFI_ALREADY_STARTED  System already register this interface.
**/
EFI_STATUS
EFIAPI
RegisterHashApiLib (
  IN HASH_INTERFACE_UNIFIED_API   *HashInterface
  )
{
//  EFI_STATUS  Status;
  UINTN       Index;
  UINT32      HashMask;
  HASH_INTERFACE_HOB *HashInterfaceHob;

  //
  // Check Allow
  //
  HashMask = GetApiHashMaskFromAlgo (&HashInterface->HashGuid);

  HashInterfaceHob = InternalGetBaseHashInterfaceHob (&gEfiCallerIdGuid);
  if (HashInterfaceHob == NULL) {
    HashInterfaceHob = InternalCreateBaseHashInterfaceHob (&gEfiCallerIdGuid);
    if (HashInterfaceHob == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
        // Initialize SupportedHashMask
        HashInterfaceHob->SupportedHashMask = 0;
    }
  }

  if (HashInterfaceHob->HashInterfaceCount >= HASH_COUNT) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Check duplication
  //
  for (Index = 0; Index < HashInterfaceHob->HashInterfaceCount; Index++) {
    if (CompareGuid (&HashInterfaceHob->HashInterface[Index].HashGuid, &HashInterface->HashGuid)) {
      DEBUG ((DEBUG_ERROR, "Hash Interface (%g) has been already registered\n", &HashInterface->HashGuid));
      return EFI_ALREADY_STARTED;
    }
  }

  //
  // Register the Hash Algo.
  //
  HashInterfaceHob->SupportedHashMask = HashInterfaceHob->SupportedHashMask | HashMask;

  CopyMem (&HashInterfaceHob->HashInterface[HashInterfaceHob->HashInterfaceCount], HashInterface, sizeof(*HashInterface));
  HashInterfaceHob->HashInterfaceCount ++;

  DEBUG ((DEBUG_INFO,"RegisterHashApiLib: HashInterfaceCount 0x%x  SupportedHashMask 0x%x \n",  HashInterfaceHob->HashInterfaceCount, HashInterfaceHob->SupportedHashMask));

  return EFI_SUCCESS;
}

/**
  The constructor function of BaseHashLib Pei.

  @param  FileHandle   The handle of FFS header the loaded driver.
  @param  PeiServices  The pointer to the PEI services.

  @retval EFI_SUCCESS           The constructor executes successfully.
  @retval EFI_OUT_OF_RESOURCES  There is no enough resource for the constructor.

**/
EFI_STATUS
EFIAPI
BaseHashLibApiPeiConstructor (
  IN EFI_PEI_FILE_HANDLE        FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
//  EFI_STATUS    Status;
  HASH_INTERFACE_HOB    *HashInterfaceHob;

  DEBUG ((DEBUG_INFO,"Calling BaseHashLibApiPeiConstructor.. \n"));


  HashInterfaceHob = InternalGetBaseHashInterfaceHob (&gZeroGuid);
  if (HashInterfaceHob == NULL) {
    //
    // No HOB with gZeroGuid Identifier has been created,
    // this is FIRST module which consumes HashLib.
    // Create the HOB with gZeroGuid Identifier.
    //
    HashInterfaceHob = InternalCreateBaseHashInterfaceHob (&gZeroGuid);
    if (HashInterfaceHob == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
  }

  HashInterfaceHob = InternalGetBaseHashInterfaceHob (&gEfiCallerIdGuid);
  if (HashInterfaceHob != NULL) {
    //
    // In PEI phase, some modules may call RegisterForShadow and will be
    // shadowed and executed again after memory is discovered.
    // This is the second execution of this module, clear the hash interface
    // information registered at its first execution.
    //
    ZeroMem (&HashInterfaceHob->HashInterface, sizeof (HashInterfaceHob->HashInterface));
    HashInterfaceHob->HashInterfaceCount = 0;
    HashInterfaceHob->SupportedHashMask = 0;
  }

  return EFI_SUCCESS;
}