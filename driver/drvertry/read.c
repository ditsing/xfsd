/*++
Module Name:
    Read.c
Abstract:
    This module implements the File Read routine for Read called by the
    Fsd/Fsp dispatch drivers.
�����read����������������ô���»�û��̫������˵
--*/

#include "XProcs.h"

//
//  The Bug check file id for this module
//

#define BugCheckFileId                   (XFS_BUG_CHECK_READ)

//
//  VOID
//  SafeZeroMemory (
//      IN PUCHAR At,
//      IN ULONG ByteCount
//      );
//

//
//  This macro just puts a nice little try-except around RtlZeroMemory
//

#define SafeZeroMemory(IC,AT,BYTE_COUNT) {                  \
    try {                                                   \
        RtlZeroMemory( (AT), (BYTE_COUNT) );                \
    } except( EXCEPTION_EXECUTE_HANDLER ) {                 \
         XRaiseStatus( IC, STATUS_INVALID_USER_BUFFER );   \
    }                                                       \
}

//
// Read ahead amount used for normal data files
//

#define READ_AHEAD_GRANULARITY           (0x10000)

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, XCommonRead)
#endif


NTSTATUS
XCommonRead (
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )

/*++

Routine Description:

    This is the common entry point for XReadFile calls.  For synchronous requests,
    CommonRead will complete the request in the current thread.  If not
    synchronous the request will be passed to the Fsp if there is a need to
    block.

Arguments:

    Irp - Supplies the Irp to process

Return Value:

    NTSTATUS - The result of this operation.

--*/

{
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );

    TYPE_OF_OPEN TypeOfOpen;
//�øĳ�ʲô�أ�
    PFCB Fcb;
    PCCB Ccb;

    BOOLEAN Wait;
    ULONG PagingIo;
    ULONG SynchronousIo;
    ULONG NonCachedIo;
    PVOID UserBuffer;

    LONGLONG StartingOffset;
    LONGLONG ByteRange;
    ULONG ByteCount;
    ULONG ReadByteCount;
    ULONG OriginalByteCount;

    PVOID SystemBuffer;

    BOOLEAN ReleaseFile = TRUE;

    X_IO_CONTEXT LocalIoContext;

    PAGED_CODE();

    //
    //  read����Ϊ0��ֱ�ӷ��سɹ�
    //

    if (IrpSp->Parameters.Read.Length == 0) {

        XCompleteRequest( IrpContext, Irp, STATUS_SUCCESS );
        return STATUS_SUCCESS;
    }


    // �����ļ����󣬶�������ǺϷ��ģ��ļ���֧�ֵĸ�ʽ��

    TypeOfOpen = XDecodeFileObject( IrpContext, IrpSp->FileObject, &Fcb, &Ccb );

    if ((TypeOfOpen == UnopenedFileObject) ||
        (TypeOfOpen == UserDirectoryOpen)) {

        XCompleteRequest( IrpContext, Irp, STATUS_INVALID_DEVICE_REQUEST );
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // 
    //  Examine our input parameters to determine if this is noncached and/or
    //  a paging io operation.
    //

    Wait = BooleanFlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );
    PagingIo = FlagOn( Irp->Flags, IRP_PAGING_IO );
    NonCachedIo = FlagOn( Irp->Flags, IRP_NOCACHE );
    SynchronousIo = FlagOn( IrpSp->FileObject->Flags, FO_SYNCHRONOUS_IO );


    //
    //  Extract the range of the Io.
    //

    StartingOffset = IrpSp->Parameters.Read.ByteOffset.QuadPart;
    OriginalByteCount = ByteCount = IrpSp->Parameters.Read.Length;

    ByteRange = StartingOffset + ByteCount;

    //
    //  Make sure that Dasd access is always non-cached.
    //

    if (TypeOfOpen == UserVolumeOpen) {

        NonCachedIo = TRUE;
    }

    //
    //  Acquire the file shared to perform the read.  If we are doing paging IO,
    //  it may be the case that we would have a deadlock imminent because we may
    //  block on shared access, so starve out any exclusive waiters.  This requires
    //  a degree of caution - we believe that any paging IO bursts will recede and
    //  allow the exclusive waiter in.
    //

    if (PagingIo) {

        XAcquireFileSharedStarveExclusive( IrpContext, Fcb );
    
    } else {
        
        XAcquireFileShared( IrpContext, Fcb );
    }

    //
    //  Use a try-finally to facilitate cleanup.
    //

    try {

        //
        //  Verify the Fcb.  Allow reads if this is a DASD handle that is 
        //  dismounting the volume.
        //

        if ((TypeOfOpen != UserVolumeOpen) || (NULL == Ccb) ||
            !FlagOn( Ccb->Flags, CCB_FLAG_DISMOUNT_ON_CLOSE))  {
        
            XVerifyFcbOperation( IrpContext, Fcb );
        }

        //
        //  If this is a non-cached then check whether we need to post this
        //  request if this thread can't block.
        //

        if (!Wait && NonCachedIo) {

            //
            //  XA requests must always be waitable.
            //

            if (FlagOn( Fcb->FcbState, FCB_STATE_RAWSECTOR_MASK )) {

                SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_FORCE_POST );
                try_return( Status = STATUS_CANT_WAIT );
            }
        }

        //
        //  If this is a user request then verify the oplock and filelock state.
        //

        if (TypeOfOpen == UserFileOpen) {

            //
            //  ����file oplocks��״̬�����Ƿ����
            //

            Status = FsRtlCheckOplock( &Fcb->Oplock,
                                       Irp,
                                       IrpContext,
                                       XOplockComplete,
                                       XPrePostIrp );

            //
            //  If the result is not STATUS_SUCCESS then the Irp was completed
            //  elsewhere.
            //

            if (Status != STATUS_SUCCESS) {

                Irp = NULL;
                IrpContext = NULL;

                try_return( NOTHING );
            }

            if (!PagingIo &&
                (Fcb->FileLock != NULL) &&
                !FsRtlCheckLockForReadAccess( Fcb->FileLock, Irp )) {

                try_return( Status = STATUS_FILE_LOCK_CONFLICT );
            }
        }

        //
        //  Complete the request if it begins beyond the end of file.
        //

        if (StartingOffset >= Fcb->FileSize.QuadPart) {

            try_return( Status = STATUS_END_OF_FILE );
        }

        //
        //  Truncate the read if it extends beyond the end of the file.
        //

        if (ByteRange > Fcb->FileSize.QuadPart) {

            ByteCount = (ULONG) (Fcb->FileSize.QuadPart - StartingOffset);
            ByteRange = Fcb->FileSize.QuadPart;
        }

        //
        //  Handle the non-cached read first.
        //

        if (NonCachedIo) {

            //
            //  If we have an unaligned transfer then post this request if
            //  we can't wait.  Unaligned means that the starting offset
            //  is not on a sector boundary or the read is not integral
            //  sectors.
            //

            ReadByteCount = BlockAlign( Fcb->Vcb, ByteCount );

            if (SectorOffset( StartingOffset ) ||
                SectorOffset( ReadByteCount ) ||
                (ReadByteCount > OriginalByteCount)) {

                if (!Wait) {

                    XRaiseStatus( IrpContext, STATUS_CANT_WAIT );
                }

                //
                //  ȷ��û����д������.
                //

                ReadByteCount = ByteCount;
            }

            //
            //  Initialize the IoContext for the read.
            //  If there is a context pointer, we need to make sure it was
            //  allocated and not a stale stack pointer.
            //

            if (IrpContext->IoContext == NULL ||
                !FlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_IO )) {

                //
                //  If we can wait, use the context on the stack.  Otherwise
                //  we need to allocate one.
                //

                if (Wait) {

                    IrpContext->IoContext = &LocalIoContext;
                    ClearFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_IO );

                } else {

                    IrpContext->IoContext = XAllocateIoContext();
                    SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_IO );
                }
            }

            RtlZeroMemory( IrpContext->IoContext, sizeof( X_IO_CONTEXT ));

            //
            //  Store whether we allocated this context structure in the structure
            //  itself.
            //

            IrpContext->IoContext->AllocatedContext =
                BooleanFlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_IO );

            if (Wait) {

                KeInitializeEvent( &IrpContext->IoContext->SyncEvent,
                                   NotificationEvent,
                                   FALSE );

            } else {

                IrpContext->IoContext->ResourceThreadId = ExGetCurrentResourceThread();
                IrpContext->IoContext->Resource = Fcb->Resource;
                IrpContext->IoContext->RequestedByteCount = ByteCount;
            }

            Irp->IoStatus.Information = ReadByteCount;

            //
            //  Call one of the NonCacheIo routines to perform the actual
            //  read.
            //

            if (FlagOn( Fcb->FcbState, FCB_STATE_RAWSECTOR_MASK )) {

                Status = XNonCachedXARead( IrpContext, Fcb, StartingOffset, ReadByteCount );

            } else {

                Status = XNonCachedRead( IrpContext, Fcb, StartingOffset, ReadByteCount );
            }
            
            //  ���STATUS_PENDING�����أ�����ɴ�����
            
            if (Status == STATUS_PENDING) {

                Irp = NULL;
                ReleaseFile = FALSE;

            //
            //  Test is we should zero part of the buffer or update the
            //  synchronous file position.
            //

            } else {

                //
                //  Convert any unknown error code to IO_ERROR.
                //

                if (!NT_SUCCESS( Status )) {

                    //  ����Ϣ��Ϊ0

                    Irp->IoStatus.Information = 0;

                    //
                    //  Raise if this is a user induced error.
                    //

                    if (IoIsErrorUserInduced( Status )) {

                        XRaiseStatus( IrpContext, Status );
                    }

                    Status = FsRtlNormalizeXstatus( Status, STATUS_UNEXPECTED_IO_ERROR );

                //
                //  Check if there is any portion of the user's buffer to zero.
                //

                } else if (ReadByteCount != ByteCount) {

                    XMapUserBuffer( IrpContext, &UserBuffer);
                    
                    SafeZeroMemory( IrpContext,
                                    Add2Ptr( UserBuffer,
                                             ByteCount,
                                             PVOID ),
                                    ReadByteCount - ByteCount );

                    Irp->IoStatus.Information = ByteCount;
                }

                //
                //  Update the file position if this is a synchronous request.
                //

                if (SynchronousIo && !PagingIo && NT_SUCCESS( Status )) {

                    IrpSp->FileObject->CurrentByteOffset.QuadPart = ByteRange;
                }
            }

            try_return( NOTHING );
        }

        //
        //  Handle the cached case.  Start by initializing the private
        //  cache map.
        //

        if (IrpSp->FileObject->PrivateCacheMap == NULL) {

            //  ��ʼ��cachemap

            CcInitializeCacheMap( IrpSp->FileObject,
                                  (PCC_FILE_SIZES) &Fcb->AllocationSize,
                                  FALSE,
                                  &XData.CacheManagerCallbacks,
                                  Fcb );

            CcSetReadAheadGranularity( IrpSp->FileObject, READ_AHEAD_GRANULARITY );
        }

        //
        //  Read from the cache if this is not an Mdl read.
        //

        if (!FlagOn( IrpContext->MinorFunction, IRP_MN_MDL )) {

            //
            // If we are in the Fsp now because we had to wait earlier,
            // we must map the user buffer, otherwise we can use the
            // user's buffer directly.
            //

            XMapUserBuffer( IrpContext, &SystemBuffer );

            //
            // Now try to do the copy.
            //

            if (!CcCopyRead( IrpSp->FileObject,
                             (PLARGE_INTEGER) &StartingOffset,
                             ByteCount,
                             Wait,
                             SystemBuffer,
                             &Irp->IoStatus )) {

                try_return( Status = STATUS_CANT_WAIT );
            }

            //  ���ò��ɹ������ش���״̬

            if (!NT_SUCCESS( Irp->IoStatus.Status )) {

                XNormalizeAndRaiseStatus( IrpContext, Irp->IoStatus.Status );
            }

        //
        //  Otherwise perform the MdlRead operation.
        //

        } else {

            CcMdlRead( IrpSp->FileObject,
                       (PLARGE_INTEGER) &StartingOffset,
                       ByteCount,
                       &Irp->MdlAddress,
                       &Irp->IoStatus );

            Status = Irp->IoStatus.Status;
        }

        //  ����ǰ�ļ�λ�ø��µ��û��ļ�����

        if (SynchronousIo && !PagingIo && NT_SUCCESS( Status )) {

            IrpSp->FileObject->CurrentByteOffset.QuadPart = ByteRange;
        }

    try_exit:  NOTHING;
    } finally {

        //
        //  Release the Fcb.
        //

        if (ReleaseFile) {

            XReleaseFile( IrpContext, Fcb );
        }
    }

    //
    //  Post the request if we got CANT_WAIT.
    //

    if (Status == STATUS_CANT_WAIT) {

        Status = XFsdPostRequest( IrpContext, Irp );

    //
    //  Otherwise complete the request.
    //

    } else {

        XCompleteRequest( IrpContext, Irp, Status );
    }

    return Status;
}

