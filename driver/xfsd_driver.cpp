#include "stdafx.h"

void xfsd_driverUnload(IN PDRIVER_OBJECT DriverObject);
DRIVER_DISPATCH xfsd_driverDefaultHandler;
NTSTATUS xfsd_driverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#ifdef __cplusplus
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath);
extern "C"
{
#include "tslib/tslib.h"
#include "tslib/read_file2.h"
}
#endif

NTSTATUS try_open_device( UNICODE_STRING device);

NTSTATUS xfsd_driver_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS xfsd_driver_filesystem_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS xfsd_driver_create( IN PDEVICE_OBJECT DevObj, IN PIRP Irp);
NTSTATUS xfsd_driver_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS xfsd_driver_info( IN PDEVICE_OBJECT DevObj, IN PIRP Irp);
NTSTATUS xfsd_driver_vol_info(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS xfsd_driver_directory_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

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

typedef struct _xfsd_vcb
{
	PVPB vpb;
	tslib_file_p root_dir;
} xfsd_vcb;

typedef struct _xfsd_ccb
{
	UNICODE_STRING pattern;
	ULONG offset;
	ULONG inuse;
} xfsd_ccb;

void init_test()
{
	char test_cache[101];
	DbgBreakPoint();
	tslib_file_p test_file = open_file2("xfsd_types.h");
	if ( test_file)
	{
		long long ret = read_file2( test_file, test_cache, 100);
		test_cache[100] = '\0';
		KdPrint(("Read length %lld %s\n", ret, test_cache));
	}
	else
	{
		KdPrint(("Open test file failed.\n"));
		DbgBreakPoint();
	}
	DbgBreakPoint();
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	if ( tslib_init())
	{
		KdPrint(("INIT ERROR!\n"));
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	init_test();

	UNICODE_STRING DeviceName,Win32Device;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;
	unsigned i;

	RtlInitUnicodeString(&DeviceName,L"\\Device\\xfsd_driver");
	RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\xfsd_driver");

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = xfsd_driverDefaultHandler;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = xfsd_driver_create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = xfsd_driver_close;
	DriverObject->MajorFunction[IRP_MJ_READ] = xfsd_driver_read;
	DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = xfsd_driver_filesystem_control;
	DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = xfsd_driver_vol_info;
	DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = xfsd_driver_info;
	DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = xfsd_driver_directory_control;
	
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

                VolumeLabelLength = 4;

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

				Buffer->VolumeLabel[0] = (WCHAR)'X';
				Buffer->VolumeLabel[1] = (WCHAR)'F';
				Buffer->VolumeLabel[2] = (WCHAR)'S';
				Buffer->VolumeLabel[3] = (WCHAR)'D';
//				Buffer->VolumeLabel[4] = (WCHAR)'\0';

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

                Buffer->FileSystemNameLength = 4 * 2;

                RequiredLength = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) +
                    4 * 2 - sizeof(WCHAR);

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
//				Buffer->FileSystemName[4] = (WCHAR)'\0';

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

	irpsp = Irp->Tail.Overlay.CurrentStackLocation;
	switch ( irpsp->MajorFunction)
	{
	case IRP_MJ_CLOSE:
		name = "IRP_MJ_CLOSE";
		break;
	case IRP_MJ_READ:
		name = "IRP_MJ_READ";
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
	case IRP_MJ_FLUSH_BUFFERS:
	case IRP_MJ_SHUTDOWN:
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_DISK_INCREMENT);
		break;
	default:
		KdPrint(("Unexpected major function: %#x\n", irpsp->MajorFunction ));
	};
	KdPrint(("Get IRP:: %s at %p\n", name, DeviceObject));
	return Irp->IoStatus.Status;
}

NTSTATUS xfsd_driver_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	IrpContext *irpc = xfsd_alloc_irpc( DeviceObject, Irp);
	NTSTATUS status = STATUS_SUCCESS;

	ExFreePool(irpc);
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS xfsd_driver_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	IrpContext *irpc = xfsd_alloc_irpc( DeviceObject, Irp);
	NTSTATUS status;
	ULONG len = irpc->sp->Parameters.Read.Length;
	LARGE_INTEGER offset = irpc->sp->Parameters.Read.ByteOffset;
	PVOID userbuffer = Irp->UserBuffer;

	tslib_file_p fcb = (tslib_file_p)irpc->file->FsContext;
	__try
	{
		if ( irpc->MinorFunction != IRP_MN_NORMAL)
		{
			status = STATUS_NOT_SUPPORTED;
			__leave;
		}

		if (Irp->RequestorMode != KernelMode &&
            !Irp->MdlAddress &&
            Irp->UserBuffer)
        {
            ProbeForWrite(Irp->UserBuffer, len, 1);
        }

		if ( !tslib_file_seek( fcb, offset.QuadPart))
		{
			status = STATUS_INVALID_PARAMETER;
			__leave;
		}

		SSIZE_T retlen = read_file2( fcb, userbuffer, len);
		status = retlen >= 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		len = retlen;
	}
	__finally
	{
		ExFreePool(irpc);
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = NT_SUCCESS(status) ? len : 0;
		IoCompleteRequest(Irp, NT_SUCCESS(status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
	}

	return status;
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
	LARGE_INTEGER		Offset;
	Offset.QuadPart = 0;

	Buffer = (PCHAR)ExAllocatePool( NonPagedPool, Length);
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildSynchronousFsdRequest(
        IRP_MJ_READ,
        dev,
        (PVOID)Buffer,
        Length,
		&Offset,
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
			sizeof(xfsd_vcb),
			NULL,
			FILE_DEVICE_DISK_FILE_SYSTEM,
			0,
			FALSE,
			&fs_vol);

		if ( !NT_SUCCESS(status))
		{
			__leave;
		}
		xfsd_vcb *vcb = ( xfsd_vcb *)fs_vol->DeviceExtension;
		vcb->root_dir = tslib_file_get_root_dir();
		vcb->vpb = irpc->sp->Parameters.MountVolume.Vpb;

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
    }
	irpc->irp->IoStatus.Status = Status;
	IoCompleteRequest(irpc->irp, IO_NO_INCREMENT);

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

	ExFreePool(irpc);
	return status;
}

NTSTATUS xfsd_driver_lookup( PFILE_OBJECT file)
{
	xfsd_vcb *vcb = (xfsd_vcb *)fs_vol->DeviceExtension; 
	ULONG cache_l = file->FileName.Length >> 1;
	CHAR *cache = ( CHAR *)ExAllocatePool( PagedPool, cache_l + 1);
	xfsd_driver_wchar_to_char( cache, file->FileName.Buffer, cache_l);
	*(cache + cache_l) = '\0';

	PCHAR leg = cache;
	tslib_file_p fcb = vcb->root_dir;

	if ( *leg == '\\')
	{
		++leg;
		if ( !*leg)
		{
			++leg;
		}
	}
	else
	{
		PFILE_OBJECT related_file = file->RelatedFileObject;
		if ( related_file && tslib_file_is_dir( ( tslib_file_p) related_file->FsContext))
		{
			fcb = ( tslib_file_p)related_file->FsContext;
		}
	}

	while ( fcb && tslib_file_is_dir( fcb) && leg != cache + cache_l + 1)
	{
		PCHAR next = leg;
		while ( *next && *next != '\\')
		{
			++next;
		}
		*next = '\0';

		fcb = open_file2_relative( fcb, leg);
		leg = next + 1;
	}

	xfsd_ccb *ccb = ( xfsd_ccb *)ExAllocatePool( NonPagedPool, sizeof( xfsd_ccb));
	ccb->offset = 0;
	ccb->inuse = 0;
	ccb->pattern.Buffer = NULL;
	ccb->pattern.Length = ccb->pattern.MaximumLength = 0;

	file->FsContext = (PVOID) fcb;
	file->FsContext2 = (PVOID) ccb;
	file->PrivateCacheMap = NULL;
	file->SectionObjectPointer = NULL;
	file->Vpb = vcb->vpb;

	ExFreePool(cache);
	return fcb ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS xfsd_driver_create( PDEVICE_OBJECT DevObj, PIRP Irp)
{
	IrpContext *irpc = xfsd_alloc_irpc( DevObj, Irp);
	PIO_STACK_LOCATION irpsp = irpc->sp;

	NTSTATUS status = STATUS_SUCCESS;
	irpc->file->FsContext = irpc->file->FsContext2 = NULL;
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
		KdPrint(("Creating file name %wZ\n", &irpsp->FileObject->FileName));
		KdPrint(("Creating file length %ld\n", (long)irpsp->FileObject->FileName.Length));

		PFILE_OBJECT file = irpsp->FileObject;
		if ( NT_SUCCESS( xfsd_driver_lookup( file)))
		{
			KdPrint(("Creating File done.\n"));
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = FILE_OPENED;
			IoCompleteRequest(Irp, IO_DISK_INCREMENT);
		}
		else
		{
			KdPrint(("Creating File Failed.\n"));
			status = Irp->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
		}
	}

	ExFreePool(irpc);
	return status;
}

NTSTATUS xfsd_driver_info( PDEVICE_OBJECT DevObj, PIRP Irp)
{
	IrpContext *irpc = xfsd_alloc_irpc( DevObj, Irp);

    PDEVICE_OBJECT          DeviceObject;
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;
    PFILE_OBJECT            FileObject;
    tslib_file_p            Fcb;
    PIO_STACK_LOCATION      IrpSp;
    FILE_INFORMATION_CLASS  FileInformationClass;
    ULONG                   Length;
    PVOID                   SystemBuffer;
    BOOLEAN                 FcbResourceAcquired = FALSE;

    __try
    {
        DeviceObject = irpc->dev;

        if (DeviceObject == fs_dev)
        {
            Status = STATUS_INVALID_DEVICE_REQUEST;
            __leave;
        }

        FileObject = irpc->file;

		Fcb = ( tslib_file_p) FileObject->FsContext;

        IrpSp = irpc->sp;

        FileInformationClass = IrpSp->Parameters.QueryFile.FileInformationClass;

        Length = IrpSp->Parameters.QueryFile.Length;

        SystemBuffer = Irp->AssociatedIrp.SystemBuffer;

        RtlZeroMemory(SystemBuffer, Length);

        switch (FileInformationClass)
        {
        case FileBasicInformation:
            {
                PFILE_BASIC_INFORMATION Buffer;

                if (Length < sizeof(FILE_BASIC_INFORMATION))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_BASIC_INFORMATION) SystemBuffer;

                Buffer->CreationTime.QuadPart = 0;

                Buffer->LastAccessTime.QuadPart = 0;

                Buffer->LastWriteTime.QuadPart = 0;

                Buffer->ChangeTime.QuadPart = 0;

				Buffer->FileAttributes = FILE_ATTRIBUTE_NORMAL;
				SetFlag( Buffer->FileAttributes, FILE_ATTRIBUTE_READONLY);
				if ( tslib_file_is_dir(Fcb))
				{
					SetFlag(Buffer->FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
				}

                Irp->IoStatus.Information = sizeof(FILE_BASIC_INFORMATION);
                Status = STATUS_SUCCESS;
                __leave;
            }

        case FileStandardInformation:
            {
                PFILE_STANDARD_INFORMATION Buffer;

                if (Length < sizeof(FILE_STANDARD_INFORMATION))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_STANDARD_INFORMATION) SystemBuffer;

                Buffer->AllocationSize.QuadPart = tslib_file_size(Fcb);
                Buffer->EndOfFile.QuadPart = tslib_file_size(Fcb);
                Buffer->NumberOfLinks = 1;
                Buffer->DeletePending = FALSE;

                Buffer->Directory = tslib_file_is_dir(Fcb);

                Irp->IoStatus.Information = sizeof(FILE_STANDARD_INFORMATION);
                Status = STATUS_SUCCESS;
                __leave;
            }

        case FileInternalInformation:
            {
                PFILE_INTERNAL_INFORMATION Buffer;

                if (Length < sizeof(FILE_INTERNAL_INFORMATION))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_INTERNAL_INFORMATION) SystemBuffer;

                // The "inode number"
				Buffer->IndexNumber.QuadPart = tslib_file_inode_number(Fcb);

                Irp->IoStatus.Information = sizeof(FILE_INTERNAL_INFORMATION);
                Status = STATUS_SUCCESS;
                __leave;
            }

        case FileEaInformation:
            {
                PFILE_EA_INFORMATION Buffer;

                if (Length < sizeof(FILE_EA_INFORMATION))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_EA_INFORMATION) SystemBuffer;

                Buffer->EaSize = 0;

                Irp->IoStatus.Information = sizeof(FILE_EA_INFORMATION);
                Status = STATUS_SUCCESS;
                __leave;
            }

        case FileNameInformation:
            {
				Status = STATUS_NOT_SUPPORTED;
                __leave;
            }

        case FilePositionInformation:
            {
                PFILE_POSITION_INFORMATION Buffer;

                if (Length < sizeof(FILE_POSITION_INFORMATION))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_POSITION_INFORMATION) SystemBuffer;

                Buffer->CurrentByteOffset = FileObject->CurrentByteOffset;

                Irp->IoStatus.Information = sizeof(FILE_POSITION_INFORMATION);
                Status = STATUS_SUCCESS;
                __leave;
            }

        case FileAllInformation:
            {
                PFILE_ALL_INFORMATION       FileAllInformation;
                PFILE_BASIC_INFORMATION     FileBasicInformation;
                PFILE_STANDARD_INFORMATION  FileStandardInformation;
                PFILE_INTERNAL_INFORMATION  FileInternalInformation;
                PFILE_EA_INFORMATION        FileEaInformation;
                PFILE_POSITION_INFORMATION  FilePositionInformation;

                if (Length < sizeof(FILE_ALL_INFORMATION))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                FileAllInformation = (PFILE_ALL_INFORMATION) SystemBuffer;

                FileBasicInformation =
                    &FileAllInformation->BasicInformation;

                FileStandardInformation =
                    &FileAllInformation->StandardInformation;

                FileInternalInformation =
                    &FileAllInformation->InternalInformation;

                FileEaInformation =
                    &FileAllInformation->EaInformation;

                FilePositionInformation =
                    &FileAllInformation->PositionInformation;

                FileBasicInformation->CreationTime.QuadPart = 0;

                FileBasicInformation->LastAccessTime.QuadPart = 0;

                FileBasicInformation->LastWriteTime.QuadPart = 0;

                FileBasicInformation->ChangeTime.QuadPart = 0;

				FileBasicInformation->FileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY;

                FileStandardInformation->AllocationSize.QuadPart = tslib_file_size(Fcb);

                FileStandardInformation->EndOfFile.QuadPart = tslib_file_size(Fcb);

                FileStandardInformation->NumberOfLinks = 1;

                FileStandardInformation->DeletePending = FALSE;

                FileStandardInformation->Directory = tslib_file_is_dir( Fcb);
				if ( tslib_file_is_dir( Fcb))
				{
					SetFlag(FileBasicInformation->FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
				}

                // The "inode number"
				FileInternalInformation->IndexNumber.QuadPart = tslib_file_inode_number( Fcb);

                // Romfs doesn't have any extended attributes
                FileEaInformation->EaSize = 0;

                FilePositionInformation->CurrentByteOffset =
                    FileObject->CurrentByteOffset;
                Status = STATUS_SUCCESS;
                __leave;
            }

        case FileNetworkOpenInformation:
            {
                PFILE_NETWORK_OPEN_INFORMATION Buffer;

                if (Length < sizeof(FILE_NETWORK_OPEN_INFORMATION))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    __leave;
                }

                Buffer = (PFILE_NETWORK_OPEN_INFORMATION) SystemBuffer;

                Buffer->CreationTime.QuadPart = 0;

                Buffer->LastAccessTime.QuadPart = 0;

                Buffer->LastWriteTime.QuadPart = 0;

                Buffer->ChangeTime.QuadPart = 0;

                Buffer->AllocationSize.QuadPart = tslib_file_size(Fcb);

                Buffer->EndOfFile.QuadPart = tslib_file_size(Fcb);

				Buffer->FileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY;
				SetFlag(Buffer->FileAttributes, FILE_ATTRIBUTE_DIRECTORY);

                Irp->IoStatus.Information =
                    sizeof(FILE_NETWORK_OPEN_INFORMATION);
                Status = STATUS_SUCCESS;
                __leave;
            }

        default:
            Status = STATUS_INVALID_INFO_CLASS;
        }
    }
    __finally
	{
		IoCompleteRequest(
			irpc->irp,
			(NT_SUCCESS(Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT)
			);

		ExFreePool(irpc);
	}

    return Status;
}

PFILE_OBJECT xfsd_driver_build_file( const char *name, int len)
{
	PFILE_OBJECT file = (PFILE_OBJECT) ExAllocatePool( NonPagedPool, sizeof(FILE_OBJECT));
	file->FileName.Buffer = (PWCHAR) ExAllocatePool( NonPagedPool, len * 2);
	xfsd_driver_char_to_wchar( file->FileName.Buffer, name, len);
	file->FileName.Length = len * 2;

	return file;
}

struct xfsd_buf_str_head
{
	xfsd_buf_str_head *next;
	int namelen;
	char *name;
};

int xfsd_driver_filldir( void *buf, const char *name, int len, long long offset,
	unsigned long long index, unsigned type)
{
	KdPrint(("filldir called with offset %d %llu\n", (int)offset), index);

	xfsd_buf_t *head = ( xfsd_buf_t *)buf;

	ULONG buf_size = head->unit + len * 2 - sizeof(WCHAR);
	ULONG buf_space = ( (buf_size >> 2) + ((buf_size & 3) ? 1 : 0)) << 2;
	KdPrint(("Need space %ld\n", buf_space));

	if ( head->unit == 0 || buf_space > head->space)
	{
		head->unit = 0;
		return 1;
	}

	head->offset = offset;

	xfsd_buf_str_head *str = ( xfsd_buf_str_head *)head->cur;

	str->namelen = len;
	str->name = ( char *)(str + 1);
	RtlCopyMemory( str->name, name, len);
	*(str->name + len) = '\0';

	str->next = ( xfsd_buf_str_head *) ( head->cur = (PVOID) ((PUCHAR)head->cur + buf_space));
	head->space -= buf_space;

	DbgBreakPoint();
	return 0;
}

VOID xfsd_driver_fill_both_dir_info( PVOID Buffer, ULONG Space, PFILE_OBJECT file);
VOID xfsd_driver_fill_dir_info( PVOID Buffer, ULONG Space, PFILE_OBJECT file);
VOID xfsd_driver_fill_full_dir_info( PVOID Buffer, ULONG Space, PFILE_OBJECT file);
VOID xfsd_driver_fill_dir_name_info( PVOID Buffer, ULONG Space, PFILE_OBJECT file);

NTSTATUS xfsd_driver_directory_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	IrpContext				*irpc = xfsd_alloc_irpc( DeviceObject, Irp);
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;
	xfsd_vcb                *Vcb = ( xfsd_vcb *) fs_vol->DeviceExtension;
    PFILE_OBJECT            FileObject;
    tslib_file_p            Fcb;
	xfsd_ccb				*Ccb;
	PIO_STACK_LOCATION      IrpSp = irpc->sp;
    FILE_INFORMATION_CLASS  FileInformationClass;
    ULONG                   Length;
    PUNICODE_STRING         FileName;
    ULONG                   FileIndex;
    BOOLEAN                 RestartScan;
    BOOLEAN                 ReturnSingleEntry;
    BOOLEAN                 IndexSpecified;
    PUCHAR                  UserBuffer;
    BOOLEAN                 FirstQuery = FALSE;
    ULONG                   QueryBlockLength;
    ULONG                   UsedLength = 0;
	xfsd_buf_t				*head = NULL;
	VOID					(* fill_info)( PVOID Buffer, ULONG Space, PFILE_OBJECT file);
	UNICODE_STRING			name;
	ANSI_STRING				ans_name;

	PVOID buf_head;
	PVOID last_assigned = NULL;
	ULONG len;

	int ret_code = 0;
	int found = 0;

	DbgBreakPoint();
    __try
    {
		if ( IrpSp->MinorFunction != IRP_MN_QUERY_DIRECTORY)
		{
			Status = STATUS_NOT_SUPPORTED;
			__leave;
		}

        if (DeviceObject == fs_dev)
        {
            Status = STATUS_INVALID_DEVICE_REQUEST;
            __leave;
        }

		FileObject = irpc->file;

        FileInformationClass =
            IrpSp->Parameters.QueryDirectory.FileInformationClass;

        Length = IrpSp->Parameters.QueryDirectory.Length;

        FileName = IrpSp->Parameters.QueryDirectory.FileName;

        FileIndex = IrpSp->Parameters.QueryDirectory.FileIndex;

        RestartScan = FlagOn(IrpSp->Flags, SL_RESTART_SCAN);
        ReturnSingleEntry = FlagOn(IrpSp->Flags, SL_RETURN_SINGLE_ENTRY);
        IndexSpecified = FlagOn(IrpSp->Flags, SL_INDEX_SPECIFIED);

		KdPrint(("Get IRP_MJ_DIRECOTORY_CONTROL Restartscan %d, ReturnSingle %d, Index %d\n",
			RestartScan, ReturnSingleEntry, IndexSpecified));
		KdPrint(("At filename %s\n", FileName->Buffer));

		Fcb = ( tslib_file_p) FileObject->FsContext;
		Ccb = ( xfsd_ccb *) FileObject->FsContext2;

        if ( !tslib_file_is_dir(Fcb))
        {
            Status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        if (Irp->RequestorMode != KernelMode &&
            !Irp->MdlAddress &&
            Irp->UserBuffer)
        {
            ProbeForWrite(Irp->UserBuffer, Length, 1);
        }

		if (Irp->MdlAddress)
		{
			KdPrint(("Using mdldress!!\n"));
			DbgBreakPoint();
			UserBuffer = (PUCHAR) MmGetSystemAddressForMdl(Irp->MdlAddress);
		}
		else
		{
			UserBuffer = (PUCHAR) Irp->UserBuffer;
		}

		if ( RestartScan || !Ccb->inuse)
		{
			FirstQuery = TRUE;
			if (FileName == NULL)
			{
				KdPrint(("NULL Filename with NULL CCB!!\n"));
				Status = STATUS_INVALID_PARAMETER;
				__leave;
			}

			xfsd_driver_init_string( &Ccb->pattern, FileName);
			Ccb->offset = 0;
			Ccb->inuse = 1;
		}

        if (UserBuffer == NULL)
        {
            Status = STATUS_INVALID_USER_BUFFER;
            __leave;
        }

        if (IndexSpecified)
        {
			KdPrint(("Using Index to query.\n"));
			Status = STATUS_NOT_SUPPORTED;
			__leave;
        }

        RtlZeroMemory(UserBuffer, Length);

        switch (FileInformationClass)
        {
        case FileDirectoryInformation:
            QueryBlockLength = sizeof(FILE_DIRECTORY_INFORMATION);
			fill_info = xfsd_driver_fill_dir_info;
            break;

        case FileFullDirectoryInformation:
            QueryBlockLength = sizeof(FILE_FULL_DIR_INFORMATION);
			fill_info = xfsd_driver_fill_full_dir_info;
            break;

        case FileNamesInformation:
            QueryBlockLength = sizeof(FILE_NAMES_INFORMATION);
			fill_info = xfsd_driver_fill_dir_name_info;
            break;

		case FileBothDirectoryInformation:
            QueryBlockLength = sizeof(FILE_BOTH_DIR_INFORMATION);
			fill_info = xfsd_driver_fill_both_dir_info;
            break;

        default:
            Status = STATUS_INVALID_PARAMETER;
            __leave;
        }
		if (Length < QueryBlockLength)
		{
			Status = STATUS_INFO_LENGTH_MISMATCH;
			__leave;
		}

		head = ( xfsd_buf_t *)ExAllocatePool( NonPagedPool, sizeof( xfsd_buf_t));
		head->cur = UserBuffer;
		head->space = Length;
		head->unit = QueryBlockLength;
		head->offset = 0;

		buf_head = UserBuffer;
		last_assigned = NULL;
		len = Length;

		ret_code = 0;
		found = 0;
		while ( len && ret_code != -1 &&
			( ret_code = tslib_readdir( Fcb, head, xfsd_driver_filldir)) <= 0)
		{
			DbgBreakPoint();
			xfsd_buf_str_head *str_head = ( xfsd_buf_str_head *)buf_head;
			while ( str_head != head->cur)
			{
				xfsd_buf_str_head *str_next = str_head->next;
				++found;

				RtlInitAnsiString( &ans_name, str_head->name);
				RtlAnsiStringToUnicodeString( &name, &ans_name, TRUE);

				KdPrint(("Got filename %wZ\n", &name));

				DbgBreakPoint();
				if ( FsRtlIsNameInExpression( &name, &Ccb->pattern, FALSE, NULL))
				{
					DbgBreakPoint();
					PFILE_OBJECT file = xfsd_driver_build_file( str_head->name, str_head->namelen);
					file->RelatedFileObject = FileObject;
					if ( NT_SUCCESS( xfsd_driver_lookup( file)))
					{
						ULONG space = (PUCHAR)str_head->next - (PUCHAR)str_head;
						fill_info( buf_head, space, file);

						last_assigned = buf_head;
						buf_head = (PUCHAR)buf_head + space;
						len -= space;

						if ( ReturnSingleEntry)
						{
							ret_code = -1;
							break;
						}
					}
					else
					{
						KdPrint(("What's the fuck with the filename ? "));
						DbgBreakPoint();
					}
				}
				DbgBreakPoint();

				str_head = str_next;
			}

			head->cur = buf_head;
			head->space = len;
			head->unit = QueryBlockLength;
		}

		if ( ret_code > 0 && found == 0)
		{
			Status = STATUS_INFO_LENGTH_MISMATCH;
		}
		else
		{
			if ( last_assigned == NULL)
			{
				Status = FirstQuery ? STATUS_NO_SUCH_FILE : STATUS_NO_MORE_FILES;
			}
			else
			{
				// Set next entry offset to zero;
				*(ULONG *) last_assigned = 0;
				UsedLength = Length - len;
				Status = STATUS_SUCCESS;
			}
		}
    }
    __finally
    {
		DbgBreakPoint();
		if ( head != NULL)
		{
			ExFreePool(head);
			if ( name.Buffer != NULL)
			{
				ExFreePool(name.Buffer);
			}
		}
		KdPrint(("Return %ld\n", Status));
		Irp->IoStatus.Information = UsedLength;
		Irp->IoStatus.Status = Status;
		IoCompleteRequest( Irp, (NT_SUCCESS(Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT) );

		ExFreePool(irpc);
    }

	return Status;
}

VOID xfsd_driver_fill_both_dir_info( PVOID Buffer, ULONG Space, PFILE_OBJECT file)
{
	tslib_file_p fcb = ( tslib_file_p)file->FsContext;

	PFILE_BOTH_DIR_INFORMATION info = (PFILE_BOTH_DIR_INFORMATION) Buffer;
	info->NextEntryOffset = Space;
	info->FileIndex = tslib_file_inode_number( fcb);
	info->CreationTime.QuadPart =
		info->LastAccessTime.QuadPart =
		info->ChangeTime.QuadPart =
		info->LastWriteTime.QuadPart = 0;
	info->AllocationSize.QuadPart = info->EndOfFile.QuadPart = tslib_file_size( fcb);

	info->FileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY;
	if ( tslib_file_is_dir( fcb))
	{
		SetFlag( info->FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
	}

	info->EaSize = 0;
	info->FileNameLength = file->FileName.Length;
	RtlCopyMemory( info->FileName, file->FileName.Buffer, info->FileNameLength * 2);
	// TODO Short names.
}

VOID xfsd_driver_fill_dir_info( PVOID Buffer, ULONG Space, PFILE_OBJECT file)
{
	tslib_file_p fcb = ( tslib_file_p)file->FsContext;

	PFILE_DIRECTORY_INFORMATION info = (PFILE_DIRECTORY_INFORMATION) Buffer;
	info->NextEntryOffset = Space;
	info->FileIndex = tslib_file_inode_number( fcb);
	info->CreationTime.QuadPart =
		info->LastAccessTime.QuadPart =
		info->ChangeTime.QuadPart =
		info->LastWriteTime.QuadPart = 0;
	info->AllocationSize.QuadPart = info->EndOfFile.QuadPart = tslib_file_size( fcb);

	info->FileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY;
	if ( tslib_file_is_dir( fcb))
	{
		SetFlag( info->FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
	}

	info->FileNameLength = file->FileName.Length;
	RtlCopyMemory( info->FileName, file->FileName.Buffer, info->FileNameLength * 2);
}

VOID xfsd_driver_fill_full_dir_info( PVOID Buffer, ULONG Space, PFILE_OBJECT file)
{
	tslib_file_p fcb = ( tslib_file_p)file->FsContext;

	PFILE_FULL_DIR_INFORMATION info = (PFILE_FULL_DIR_INFORMATION) Buffer;

	info->NextEntryOffset = Space;
	info->FileIndex = tslib_file_inode_number( fcb);
	info->CreationTime.QuadPart =
		info->LastAccessTime.QuadPart =
		info->ChangeTime.QuadPart =
		info->LastWriteTime.QuadPart = 0;
	info->AllocationSize.QuadPart = info->EndOfFile.QuadPart = tslib_file_size( fcb);

	info->FileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY;
	if ( tslib_file_is_dir( fcb))
	{
		SetFlag( info->FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
	}

	info->EaSize = 0;

	info->FileNameLength = file->FileName.Length;
	RtlCopyMemory( info->FileName, file->FileName.Buffer, info->FileNameLength * 2);
}

VOID xfsd_driver_fill_dir_name_info( PVOID Buffer, ULONG Space, PFILE_OBJECT file)
{
	tslib_file_p fcb = ( tslib_file_p)file->FsContext;

	PFILE_NAMES_INFORMATION info = (PFILE_NAMES_INFORMATION) Buffer;

	info->NextEntryOffset = Space;

	info->FileIndex = tslib_file_inode_number( fcb);

	info->FileNameLength = file->FileName.Length;
	RtlCopyMemory( info->FileName, file->FileName.Buffer, info->FileNameLength * 2);
}