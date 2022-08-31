/** @file
  This file defines the hob structure for the Secure boot information.

  Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SECUREBOOT_INFO_GUID_H__
#define __SECUREBOOT_INFO_GUID_H__

///
/// Secure Boot info Hob GUID
///
extern EFI_GUID gSecureBootInfoGuid;

typedef struct {
  UINT8  Revision;
  UINT8  VerifiedBoot;
  UINT8  MeasuredBootEnabled;
  UINT8  FirmwareDebuggerInitialized;  
  UINT32 PcrActivePcrBanks;
} SECUREBOOT_INFO;

#endif
