/** @file
  This driver will report some MMIO/IO resources to dxe core, extract smbios and acpi
  tables from bootloader.

  Copyright (c) 2014 - 2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include "BlSupportDxe.h"


#include <Guid/TcgEventHob.h>
#include <Guid/TpmInstance.h>
#include <Library/DebugLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/PcdLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <Guid/TpmEventLogInfoGuid.h>
#include <Guid/SecureBootInfoGuid.h>

/**
  Reserve MMIO/IO resource in GCD

  @param  IsMMIO        Flag of whether it is mmio resource or io resource.
  @param  GcdType       Type of the space.
  @param  BaseAddress   Base address of the space.
  @param  Length        Length of the space.
  @param  Alignment     Align with 2^Alignment
  @param  ImageHandle   Handle for the image of this driver.

  @retval EFI_SUCCESS   Reserve successful
**/
EFI_STATUS
ReserveResourceInGcd (
  IN BOOLEAN               IsMMIO,
  IN UINTN                 GcdType,
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length,
  IN UINTN                 Alignment,
  IN EFI_HANDLE            ImageHandle
  )
{
  EFI_STATUS               Status;

  if (IsMMIO) {
    Status = gDS->AddMemorySpace (
                    GcdType,
                    BaseAddress,
                    Length,
                    EFI_MEMORY_UC
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_WARN,
        "Failed to add memory space :0x%lx 0x%lx\n",
        BaseAddress,
        Length
        ));
    }
    Status = gDS->AllocateMemorySpace (
                    EfiGcdAllocateAddress,
                    GcdType,
                    Alignment,
                    Length,
                    &BaseAddress,
                    ImageHandle,
                    NULL
                    );
  } else {
    Status = gDS->AddIoSpace (
                    GcdType,
                    BaseAddress,
                    Length
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_WARN,
        "Failed to add IO space :0x%lx 0x%lx\n",
        BaseAddress,
        Length
        ));
    }
    Status = gDS->AllocateIoSpace (
                    EfiGcdAllocateAddress,
                    GcdType,
                    Alignment,
                    Length,
                    &BaseAddress,
                    ImageHandle,
                    NULL
                    );
  }
  return Status;
}

/**
Sync the Secure boot hob info and TPM PCD as per the information passed from Bootloader.
**/
EFI_STATUS
BlSupportSecurityPcdSync (
  VOID
  )
{
  EFI_STATUS                        Status;
  EFI_HOB_GUID_TYPE                 *GuidHob;
  SECUREBOOT_INFO                   *SecurebootInfoHob;
  UINTN                              Size;

  GuidHob = GetFirstGuidHob (&gSecureBootInfoGuid);
  if (GuidHob == NULL) {
    DEBUG ((EFI_D_ERROR, "gSecureBootInfoGuid Not Found!\n"));
    return EFI_UNSUPPORTED;
  }

  SecurebootInfoHob = (SECUREBOOT_INFO *) GET_GUID_HOB_DATA(GuidHob);

  // Sync the Hash mask for TPM 2.0 as per active PCR banks.
  // Make sure that the current PCR allocations, the TPM supported PCRs,
  // and the PcdTpm2HashMask are all in agreement.
  Status = PcdSet32S (PcdTpm2HashMask, SecurebootInfoHob->TpmPcrActivePcrBanks);
  ASSERT_EFI_ERROR (Status);
  DEBUG ((DEBUG_INFO, "TpmPcrActivePcrBanks 0x%x \n", SecurebootInfoHob->TpmPcrActivePcrBanks));

  // Set the Firmware debugger PCD
  Status = PcdSetBoolS (PcdFirmwareDebuggerInitialized, SecurebootInfoHob->FirmwareDebuggerInitialized);
  ASSERT_EFI_ERROR (Status);
  DEBUG ((DEBUG_INFO, " FirmwareDebugger Initialized 0x%x \n", SecurebootInfoHob->FirmwareDebuggerInitialized));

  // Set the TPM Type instance GUID
  if (SecurebootInfoHob->MeasuredBootEnabled) {  
    if (SecurebootInfoHob->TpmType == TPM_TYPE_20) {
      DEBUG ((DEBUG_INFO, "%a: TPM2 detected\n", __FUNCTION__));
      Size = sizeof (gEfiTpmDeviceInstanceTpm20DtpmGuid);
        Status = PcdSetPtrS (
                   PcdTpmInstanceGuid,
                   &Size,
                   &gEfiTpmDeviceInstanceTpm20DtpmGuid
                   );
    } else if (SecurebootInfoHob->TpmType == TPM_TYPE_12) {
      DEBUG ((DEBUG_INFO, "%a: TPM1.2 detected\n", __FUNCTION__));
      Size = sizeof (gEfiTpmDeviceInstanceTpm12Guid);
      Status = PcdSetPtrS (
                 PcdTpmInstanceGuid,
                 &Size,
                 &gEfiTpmDeviceInstanceTpm12Guid
                 );
    } else {
      DEBUG ((DEBUG_INFO, "%a: TPM1.2 detected\n", __FUNCTION__));
      Size = sizeof (gEfiTpmDeviceInstanceNoneGuid);
      Status = PcdSetPtrS (
                 PcdTpmInstanceGuid,
                 &Size,
                 &gEfiTpmDeviceInstanceNoneGuid
                 );
    }
    ASSERT_EFI_ERROR (Status);
  }

  return Status;
}


/**
  Main entry for the bootloader support DXE module.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
BlDxeEntryPoint (
  IN EFI_HANDLE              ImageHandle,
  IN EFI_SYSTEM_TABLE        *SystemTable
  )
{
  EFI_STATUS Status;
  EFI_HOB_GUID_TYPE          *GuidHob;
  EFI_PEI_GRAPHICS_INFO_HOB  *GfxInfo;
  ACPI_BOARD_INFO            *AcpiBoardInfo;

  Status = EFI_SUCCESS;
  //
  // Report MMIO/IO Resources
  //
  ReserveResourceInGcd (TRUE, EfiGcdMemoryTypeMemoryMappedIo, 0xFEC00000, SIZE_4KB, 0, ImageHandle); // IOAPIC

   (TRUE, EfiGcdMemoryTypeMemoryMappedIo, 0xFED00000, SIZE_1KB, 0, ImageHandle); // HPET

  //
  // Find the frame buffer information and update PCDs
  //
  GuidHob = GetFirstGuidHob (&gEfiGraphicsInfoHobGuid);
  if (GuidHob != NULL) {
    GfxInfo = (EFI_PEI_GRAPHICS_INFO_HOB *)GET_GUID_HOB_DATA (GuidHob);
    Status = PcdSet32S (PcdVideoHorizontalResolution, GfxInfo->GraphicsMode.HorizontalResolution);
    ASSERT_EFI_ERROR (Status);
    Status = PcdSet32S (PcdVideoVerticalResolution, GfxInfo->GraphicsMode.VerticalResolution);
    ASSERT_EFI_ERROR (Status);
    Status = PcdSet32S (PcdSetupVideoHorizontalResolution, GfxInfo->GraphicsMode.HorizontalResolution);
    ASSERT_EFI_ERROR (Status);
    Status = PcdSet32S (PcdSetupVideoVerticalResolution, GfxInfo->GraphicsMode.VerticalResolution);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Set PcdPciExpressBaseAddress and PcdPciExpressBaseSize by HOB info
  //
  GuidHob = GetFirstGuidHob (&gUefiAcpiBoardInfoGuid);
  if (GuidHob != NULL) {
    AcpiBoardInfo = (ACPI_BOARD_INFO *)GET_GUID_HOB_DATA (GuidHob);
    Status = PcdSet64S (PcdPciExpressBaseAddress, AcpiBoardInfo->PcieBaseAddress);
    ASSERT_EFI_ERROR (Status);
    Status = PcdSet64S (PcdPciExpressBaseSize, AcpiBoardInfo->PcieBaseSize);
    ASSERT_EFI_ERROR (Status);
  }

  BlSupportSecurityPcdSync ();

  return EFI_SUCCESS;
}