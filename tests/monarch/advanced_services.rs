#![allow(non_snake_case)]

use espframe::monarch::advanced_services::{
    AdvancedServiceError, AtomicRcwInfo, AtomicRcwOperation, AtomicRcwService, ExceptionReturnInfo,
    ExceptionReturnService, GcsInfo, GcsOperation, GcsService, MemoryTagInfo, MemoryTagOperation,
    MemoryTagService, MopsInfo, MopsOperation, MopsService, RejectAtomicRcwService,
    RejectExceptionReturnService, RejectGcsService, RejectMemoryTagService, RejectMopsService,
    RejectStore64Service, Store64Info, Store64Operation, Store64Service,
};

#[test]
fn RejectAtomicRcwServiceReturnsTypedUnavailableError() {
    let service = RejectAtomicRcwService;
    let error = service
        .Process(
            7,
            AtomicRcwInfo {
                pc: 0x1000,
                address: 0x2000,
                operation: AtomicRcwOperation::CompareSwap,
                software_checks: true,
                element_count: 2,
                compare: [11, 22],
                operand: [33, 44],
            },
        )
        .unwrap_err();

    assert_eq!(
        error,
        AdvancedServiceError::AtomicRcwUnavailable(AtomicRcwOperation::CompareSwap)
    );
}

#[test]
fn RejectMemoryTagServiceReturnsTypedUnavailableError() {
    let service = RejectMemoryTagService;
    let error = service
        .Process(
            7,
            MemoryTagInfo {
                pc: 0x3000,
                address: 0x4000,
                operation: MemoryTagOperation::StoreMultiple,
                value: 0xA,
                granule_count: 4,
                zero_data: true,
            },
        )
        .unwrap_err();

    assert_eq!(
        error,
        AdvancedServiceError::MemoryTagUnavailable(MemoryTagOperation::StoreMultiple)
    );
}

#[test]
fn RejectStore64ServiceReturnsTypedUnavailableError() {
    let service = RejectStore64Service;
    let error = service
        .Process(
            7,
            Store64Info {
                pc: 0x5000,
                address: 0x6000,
                operation: Store64Operation::StoreWithStatusAndAccdata,
                data: [1, 2, 3, 4, 5, 6, 7, 8],
            },
        )
        .unwrap_err();

    assert_eq!(
        error,
        AdvancedServiceError::Store64Unavailable(Store64Operation::StoreWithStatusAndAccdata)
    );
}

#[test]
fn RejectGcsAndExceptionReturnServicesReturnTypedUnavailableErrors() {
    let gcs = RejectGcsService;
    let gcs_error = gcs
        .Process(
            7,
            GcsInfo {
                pc: 0x7000,
                operation: GcsOperation::SwitchStackPhase2,
                reg: 19,
                value: 0xABCD,
            },
        )
        .unwrap_err();
    assert_eq!(
        gcs_error,
        AdvancedServiceError::GcsUnavailable(GcsOperation::SwitchStackPhase2)
    );

    let exception_return = RejectExceptionReturnService;
    let exception_error = exception_return
        .Process(
            7,
            ExceptionReturnInfo {
                pc: 0x7100,
                key_b: true,
            },
        )
        .unwrap_err();
    assert_eq!(
        exception_error,
        AdvancedServiceError::ExceptionReturnUnavailable
    );
}

#[test]
fn RejectMopsServiceReturnsTypedUnavailableErrorAndMopsInfoPreservesFields() {
    let service = RejectMopsService;
    let info = MopsInfo {
        pc: 0x7200,
        operation: MopsOperation::SetTagsOnly,
        destination_address: 0x8000,
        source_address: 0x8100,
        count: 96,
        fill_byte: 0x5A,
        backwards: true,
    };

    assert_eq!(info.destination_address, 0x8000);
    assert_eq!(info.source_address, 0x8100);
    assert_eq!(info.count, 96);
    assert_eq!(info.fill_byte, 0x5A);
    assert!(info.backwards);

    let error = service.Process(7, info).unwrap_err();
    assert_eq!(
        error,
        AdvancedServiceError::MopsUnavailable(MopsOperation::SetTagsOnly)
    );
}
