#include "stdafx.h"

void xfsd_driverUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS xfsd_driverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#ifdef __cplusplus
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath);
extern "C"
{
#include "tslib/tslib.h"
}
#endif

NTSTATUS xfsd_driver_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS try_open_device( UNICODE_STRING device);
NTSTATUS xfsd_driver_filesystem_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS xfsd_driver_irp_create( PDEVICE_OBJECT DevObj, PIRP Irp, PIO_STACK_LOCATION irpsp);
NTSTATUS xfsd_driver_vol_info(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

static PDEVICE_OBJECT fs_dev;
static PDEVICE_OBJECT fs_vol;

typedef struct _IrpContext
{
	PIRP irp;
	PIO_STACK_LOCATION sp;
	UCHAR MajorFunction;
	UCHAR MinorFunction;
	PDEVICE_OBJECT dev;
	PFILE_OBJECT file;
} IrpContext;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	DbgBreakPoint();
	if ( tslib_init())
	{
		KdPrint(("INIT ERROR!\n"));
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	UNICODE_STRING DeviceName,Win32Device;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;
	unsigned i;

	DbgBreakPoint();
	RtlInitUnicodeString(&DeviceName,L"\\Device\\xfsd_driver");
	RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\xfsd_driver");

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = xfsd_driverDefaultHandler;

	/*
	DriverObject->MajorFunction[IRP_MJ_CREATE] = xfsd_driverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = xfsd_driverCreateClose;
	*/
	DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = xfsd_driver_filesystem_control;
	DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = xfsd_driver_vol_info;
	
	DriverObject->DriverUnload = xfsd_driverUnload;
	status = IoCreateDevice(DriverObject,
							0,
							&DeviceName,
							FILE_DEVICE_DISK_FILE_SYSTEM,
							0,
							FALSE,
							&DeviceObject);
	if (!NT_SUCCESS(status))
		return status;
	if (!DeviceObject)
		return STATUS_UNEXPECTED_IO_ERROR;

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
	DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;
	DeviceObject->StackSize = 4;
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	IoRegisterFileSystem( DeviceObject);

	fs_dev = DeviceObject;

	DbgBreakPoint();
//	status = try_open_device( Win32Device);
//	KdPrint(("Got device status %d %ld\n", (int)status, (long) NT_SUCCESS(status)));


	return STATUS_SUCCESS;
}

NTSTATUS try_open_device( UNICODE_STRING device)
{
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK ios;
	NTSTATUS nts;
	HANDLE file;

	InitializeObjectAttributes( &attr, &device, OBJ_CASE_INSENSITIVE, NULL, NULL);
	nts = ZwOpenFile( &file, GENERIC_ALL, &attr, &ios, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	return nts;
}

void xfsd_driverUnload(IN PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unloading driver, what's the fuck."));
	UNICODE_STRING Win32Device;
	RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\xfsd_driver");
	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);
}

IrpContext *xfsd_alloc_irpc(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	IrpContext *irpc = ( IrpContext *)ExAllocatePool( NonPagedPool, sizeof( IrpContext));
	irpc->irp = Irp;
	irpc->dev = DeviceObject;
	irpc->sp = IoGetCurrentIrpStackLocation(Irp);
	irpc->file = irpc->sp->FileObject;
	irpc->MajorFunction = irpc->sp->MajorFunction;
	irpc->MinorFunction = irpc->sp->MinorFunction;

	return irpc;
}

NTSTATUS xfsd_driver_vol_info(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	KdPrint(("Get IRP_MJ_QUERY_VOLUME_INFORMATION on %p\n", DeviceObject));
	IrpContext *irpc = xfsd_alloc_irpc( DeviceObject, Irp);
	NTSTATUS status;

	__try
	{
		if ( irpc->dev != fs_vol)
		{
			status = STATUS_INVALID_DEVICE_REQUEST;
			__leave;
		}

		PIRP Irp = irpc->irp;

		PIO_STACK_LOCATION IrpSp = irpc->sp;

		FS_INFORMATION_CLASS FsInformationClass = IrpSp->Parameters.QueryVolume.FsInformationClass;

        ULONG Length = IrpSp->Parameters.QueryVolume.Length;

        PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer;

        RtlZeroMemory(SystemBuffer, Length);

        switch (FsInformationClass)
        {
        case FileFsVolumeInformation:
            {
                PFILE_FS_VOLUME_INFORMATION Buffer;
                ULONG                       VolumeLabelLength;
                ULONG                       RequiredLength;

                if (Length < sizeof(FILE_FS_VOLUME_INFORMATION))
                {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_FS_VOLUME_INFORMATION) SystemBuffer;

                Buffer->VolumeCreationTime.QuadPart = 0;

                Buffer->VolumeSerialNumber = 0xDEEDBEEF;

                VolumeLabelLength = 5;

                Buffer->VolumeLabelLength = VolumeLabelLength * 2;

                // I don't know what this means.
                Buffer->SupportsObjects = FALSE;

                RequiredLength = sizeof(FILE_FS_VOLUME_INFORMATION)
                    + VolumeLabelLength * 2 - sizeof(WCHAR);

                if (Length < RequiredLength)
                {
                    Irp->IoStatus.Information =
                        sizeof(FILE_FS_VOLUME_INFORMATION);
                    status = STATUS_BUFFER_OVERFLOW;
                    __leave;
                }

				Buffer->VolumeLabel[0] = (WCHAR)"X";
				Buffer->VolumeLabel[1] = (WCHAR)"F";
				Buffer->VolumeLabel[2] = (WCHAR)"S";
				Buffer->VolumeLabel[3] = (WCHAR)"D";
				Buffer->VolumeLabel[4] = (WCHAR)"\0";

                Irp->IoStatus.Information = RequiredLength;
                status = STATUS_SUCCESS;
                __leave;
            }

        case FileFsSizeInformation:
            {
                PFILE_FS_SIZE_INFORMATION Buffer;

                if (Length < sizeof(FILE_FS_SIZE_INFORMATION))
                {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_FS_SIZE_INFORMATION) SystemBuffer;

				Buffer->TotalAllocationUnits.QuadPart = tslib_get_sb_dblocks();
				Buffer->AvailableAllocationUnits.QuadPart = 0;

                Buffer->SectorsPerAllocationUnit = tslib_get_blksize() / tslib_get_sb_sectsize();

                Buffer->BytesPerSector = tslib_get_sb_sectsize();

                Irp->IoStatus.Information = sizeof(FILE_FS_SIZE_INFORMATION);
                status = STATUS_SUCCESS;
				break;
            }

        case FileFsDeviceInformation:
            {
                PFILE_FS_DEVICE_INFORMATION Buffer;

                if (Length < sizeof(FILE_FS_DEVICE_INFORMATION))
                {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_FS_DEVICE_INFORMATION) SystemBuffer;

				Buffer->DeviceType = FILE_DEVICE_FILE_SYSTEM;

                Buffer->Characteristics = fs_vol->Characteristics;

				SetFlag(
					Buffer->Characteristics,
					FILE_READ_ONLY_DEVICE
					);
                Irp->IoStatus.Information = sizeof(FILE_FS_DEVICE_INFORMATION);
                status = STATUS_SUCCESS;
				break;
            }

        case FileFsAttributeInformation:
            {
                PFILE_FS_ATTRIBUTE_INFORMATION  Buffer;
                ULONG                           RequiredLength;

                if (Length < sizeof(FILE_FS_ATTRIBUTE_INFORMATION))
                {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_FS_ATTRIBUTE_INFORMATION) SystemBuffer;

                Buffer->FileSystemAttributes =
                    FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;

				// BUG::MAXNameLENGTH;
                Buffer->MaximumComponentNameLength = 100000;

                Buffer->FileSystemNameLength = 5 * 2;

                RequiredLength = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) +
                    5 * 2 - sizeof(WCHAR);

                if (Length < RequiredLength)
                {
                    Irp->IoStatus.Information =
                        sizeof(FILE_FS_ATTRIBUTE_INFORMATION);
                    status = STATUS_BUFFER_OVERFLOW;
                    __leave;
                }
				Buffer->FileSystemName[0] = (WCHAR)'X';
				Buffer->FileSystemName[1] = (WCHAR)'F';
				Buffer->FileSystemName[2] = (WCHAR)'S';
				Buffer->FileSystemName[3] = (WCHAR)'D';
				Buffer->FileSystemName[3] = (WCHAR)'\0';

                Irp->IoStatus.Information = RequiredLength;
                status = STATUS_SUCCESS;
				break;
            }

        default:
            status = STATUS_INVALID_INFO_CLASS;
        }
	}
	__finally
	{
			irpc->irp->IoStatus.Status = status;
			IoCompleteRequest( irpc->irp, IO_NO_INCREMENT);
			ExFreePool( irpc);
	}

	return status;
}

NTSTATUS xfsd_driverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION irpsp;
	IrpContext *irpc;
	char *name;

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;

	irpc = xfsd_alloc_irpc( DeviceObject, Irp);
	irpsp = irpc->sp;

//	irpsp = IoGetCurrentIrpStackLocation(Irp);
	irpsp = Irp->Tail.Overlay.CurrentStackLocation;
	switch ( irpsp->MajorFunction)
	{
	case IRP_MJ_CREATE:
		xfsd_driver_irp_create( DeviceObject, Irp, irpsp);
		name = "IRP_MJ_CREATE";
		break;
	case IRP_MJ_CLOSE:
		name = "IRP_MJ_CLOSE";
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;
	case IRP_MJ_READ:
		name = "IRP_MJ_READ";
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;
	case IRP_MJ_QUERY_INFORMATION:
		name = "IRP_MJ_QUERY_INFO";
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;
	case IRP_MJ_QUERY_VOLUME_INFORMATION:
		name = "IRP_MJ_QUERY_VOLUME_INFO";
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;
	case IRP_MJ_DIRECTORY_CONTROL:
		name = "IRP_MJ_DIR_CONTROL";
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;
	case IRP_MJ_FILE_SYSTEM_CONTROL:
		name = "IRP_MJ_SYS_CONTROL";
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;
	case IRP_MJ_DEVICE_CONTROL:
		name = "IRP_MJ_DEV_CONTROL";
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;
	case IRP_MJ_CLEANUP:
		name = "IRP_MJ_CLEANUP";
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_DISK_INCREMENT);
		break;
	default:
		KdPrint(("Unexpected major function: %#x\n", irpsp->MajorFunction ));
	};
	KdPrint(("Get IRP:: %s at %p\n", name, DeviceObject));
	DbgBreakPoint();
	return Irp->IoStatus.Status;
}

NTSTATUS xfsd_driver_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS xfsd_driver_verify_magic_number( PDEVICE_OBJECT dev)
{
	KEVENT              Event;
    PIRP                Irp;
    IO_STATUS_BLOCK     IoStatus;
    NTSTATUS            Status;
    PIO_STACK_LOCATION  IoStackLocation;
	PCHAR				Buffer;
	ULONG				Length = 512;

	Buffer = (PCHAR)ExAllocatePool( NonPagedPool, Length);
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildSynchronousFsdRequest(
        IRP_MJ_READ,
        dev,
        (PVOID)Buffer,
        Length,
        0,
        &Event,
        &IoStatus
        );

    if (!Irp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoStackLocation = IoGetNextIrpStackLocation(Irp);
    SetFlag(IoStackLocation->Flags, SL_OVERRIDE_VERIFY_VOLUME);
    Status = IoCallDriver(dev, Irp);

    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(
            &Event,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        Status = IoStatus.Status;
    }
	if ( NT_SUCCESS(Status))
	{
		Status = STATUS_UNRECOGNIZED_VOLUME;
		if ( Buffer[0] == 'X' && Buffer[1] == 'F' && Buffer[2] == 'S' && Buffer[3] == 'B')
		{
			Status = STATUS_SUCCESS;
			KdPrint(("Right order in magic number.\n"));
		}
		if ( Buffer[0] == 'B' && Buffer[1] == 'S' && Buffer[2] == 'F' && Buffer[3] == 'X')
		{
			Status = STATUS_SUCCESS;
			KdPrint(("Reverse order in magic number.\n"));
		}
	}

    return Status;
}

NTSTATUS xfsd_driver_mount_volume( IrpContext *irpc)
{
	PIRP irp = irpc->irp;
	NTSTATUS status;
	__try
	{
		PDEVICE_OBJECT target = irpc->sp->Parameters.MountVolume.DeviceObject;
		KdPrint(("Attaching device %p with type %x\n", irpc->dev, target->DeviceType));

		if ( fs_vol || !NT_SUCCESS(xfsd_driver_verify_magic_number( target)))
		{
			status = STATUS_UNRECOGNIZED_VOLUME;
			__leave;
		}

		status = IoCreateDevice(
			irpc->dev->DriverObject,
			0,
			NULL,
			FILE_DEVICE_DISK_FILE_SYSTEM,
			0,
			FALSE,
			&fs_vol);

		if ( !NT_SUCCESS(status))
		{
			__leave;
		}

		(irpc->sp->Parameters.MountVolume.Vpb)->DeviceObject = fs_vol;
	}
	__finally
	{
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	return status;
}

NTSTATUS xfsd_driver_user_request ( IrpContext *irpc)
{
    ULONG               FsControlCode;
    NTSTATUS            Status;

    FsControlCode = irpc->sp->Parameters.FileSystemControl.FsControlCode;

    switch (FsControlCode)
    {
    case FSCTL_LOCK_VOLUME:
		Status = STATUS_SUCCESS;
        break;

    case FSCTL_UNLOCK_VOLUME:
		Status = STATUS_SUCCESS;
        break;

    case FSCTL_DISMOUNT_VOLUME:
        Status = STATUS_SUCCESS;
        break;

    case FSCTL_IS_VOLUME_MOUNTED:
		KdPrint(("Asked by mounted with %p %p %p\n", irpc->dev, fs_vol, fs_dev));
		Status = irpc->dev == fs_vol ? STATUS_SUCCESS : STATUS_WRONG_VOLUME;
        break;

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        irpc->irp->IoStatus.Status = Status;
        IoCompleteRequest(irpc->irp, IO_NO_INCREMENT);
    }

    return Status;
}

NTSTATUS xfsd_driver_filesystem_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	IrpContext *irpc = xfsd_alloc_irpc( DeviceObject, Irp);
	NTSTATUS status;

	KdPrint(("Get IRP_MJ_FILESYSTEM_CONTROL\n"));
	switch ( irpc->MinorFunction)
	{
	case IRP_MN_MOUNT_VOLUME:
		KdPrint(("Get mount request\n"));
		status = xfsd_driver_mount_volume( irpc);
		break;
	case IRP_MN_USER_FS_REQUEST:
		KdPrint(("Get User request\n"));
		status = xfsd_driver_user_request(irpc);
		break;
	default:
		KdPrint(("Unknown Minor Function %x\n", irpc->MinorFunction));
		status = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}
	KdPrint(("Return %ld\n", status));
	DbgBreakPoint();

	ExFreePool(irpc);
	return status;
}

NTSTATUS xfsd_driver_irp_create( PDEVICE_OBJECT DevObj, PIRP Irp, PIO_STACK_LOCATION irpsp)
{
	NTSTATUS status = STATUS_SUCCESS;
	if ( DevObj == fs_dev)
	{
		KdPrint(("opening fs_dev\n"));
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = FILE_OPENED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}
	else if ( irpsp->FileObject->FileName.Length == 0)
	{
		KdPrint(("Creating Volume %p %p\n", DevObj, fs_vol));
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = FILE_OPENED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}
	else
	{
		KdPrint(("Creating file %s\n", irpsp->FileObject->FileName.Buffer));
		status = STATUS_NOT_SUPPORTED;
	}
	return status;
}