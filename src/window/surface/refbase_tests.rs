use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Retain,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReferenceCall {
    operation: Operation,
    this: usize,
    identity: usize,
}

// 与父模块已有的引用计数模型分开，避免并行测试混入事件。
static TEST_LOCK: Mutex<()> = Mutex::new(());
static CALLS: Mutex<Vec<ReferenceCall>> = Mutex::new(Vec::new());

fn record(operation: Operation, this: *const c_void, identity: *const c_void) {
    // extern C 回调中不做断言；即使锁被其它断言污染，也不让 panic 越过 ABI 边界。
    let mut calls = CALLS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    calls.push(ReferenceCall {
        operation,
        this: this as usize,
        identity: identity as usize,
    });
}

unsafe extern "C" fn retain(this: *const c_void, identity: *const c_void) {
    record(Operation::Retain, this, identity);
}

unsafe extern "C" fn release(this: *const c_void, identity: *const c_void) {
    record(Operation::Release, this, identity);
}

fn calls() -> Vec<ReferenceCall> {
    CALLS.lock().unwrap().clone()
}

struct BinderLayoutFixture {
    storage: Box<[usize; 24]>,
    _vtable: Box<[isize; 6]>,
    binder_word: usize,
    refbase_word: usize,
}

impl BinderLayoutFixture {
    fn new(binder_word: usize, refbase_word: usize) -> Self {
        assert_ne!(binder_word, refbase_word);
        let word_size = std::mem::size_of::<usize>();
        let displacement = (refbase_word as isize - binder_word as isize) * word_size as isize;
        // ARM64 Itanium 地址点前依次是虚基偏移、offset-to-top、RTTI。
        // 对象尾部长度可以不同；生产代码必须读有符号偏移，不能固定加某个尺寸。
        let vtable = Box::new([
            displacement,
            -(binder_word as isize * word_size as isize),
            0,
            0,
            0,
            0,
        ]);
        let mut storage = Box::new([0; 24]);
        storage[binder_word] = unsafe { vtable.as_ptr().add(3) } as usize;
        // 模拟 Android 15 BpBinder 的 SYSTEM 稳定性字段，不能将它当成 mRefs。
        storage[binder_word + 1] = 0x0c;
        Self {
            storage,
            _vtable: vtable,
            binder_word,
            refbase_word,
        }
    }

    fn binder(&mut self) -> *mut c_void {
        unsafe { self.storage.as_mut_ptr().add(self.binder_word).cast() }
    }

    fn refbase(&mut self) -> *mut c_void {
        unsafe { self.storage.as_mut_ptr().add(self.refbase_word).cast() }
    }
}

fn exercise_virtual_layout(binder_word: usize, refbase_word: usize) {
    CALLS.lock().unwrap().clear();
    let mut fixture = BinderLayoutFixture::new(binder_word, refbase_word);
    let binder = fixture.binder();
    let refbase = fixture.refbase() as usize;
    assert_ne!(binder as usize, refbase);
    let mut returned = CppStrongPointerReturn::uninitialized();
    unsafe { returned.write_pointer_for_foreign_return(binder) };
    let return_identity = returned.identity() as usize;

    let owner = unsafe {
        OwnedStrongPointer::adopt_returned_as(
            &mut returned,
            RefBaseLayout::BinderVirtual,
            retain,
            release,
        )
    }
    .unwrap();
    assert_eq!(owner.pointer(), binder);
    assert_eq!(owner.raw().pointer, binder);
    let adopted_calls = calls();
    assert_eq!(adopted_calls.len(), 2);
    let owner_identity = adopted_calls[0].identity;
    assert_ne!(owner_identity, return_identity);
    assert_eq!(
        adopted_calls,
        [
            ReferenceCall {
                operation: Operation::Retain,
                this: refbase,
                identity: owner_identity,
            },
            ReferenceCall {
                operation: Operation::Release,
                this: refbase,
                identity: return_identity,
            },
        ]
    );

    let duplicate = unsafe { owner.retain(retain) };
    assert_eq!(duplicate.pointer(), binder);
    assert_eq!(duplicate.raw().pointer, binder);
    let copied_calls = calls();
    assert_eq!(copied_calls.len(), 3);
    let duplicate_identity = copied_calls[2].identity;
    assert_ne!(duplicate_identity, owner_identity);
    assert_eq!(
        copied_calls[2],
        ReferenceCall {
            operation: Operation::Retain,
            this: refbase,
            identity: duplicate_identity,
        }
    );

    drop(owner);
    // 原 owner 释放后，副本仍保留原始 IBinder 接口指针。
    assert_eq!(duplicate.raw().pointer, binder);
    drop(duplicate);
    let final_calls = calls();
    assert_eq!(final_calls.len(), 5);
    assert_eq!(
        &final_calls[3..],
        [
            ReferenceCall {
                operation: Operation::Release,
                this: refbase,
                identity: owner_identity,
            },
            ReferenceCall {
                operation: Operation::Release,
                this: refbase,
                identity: duplicate_identity,
            },
        ]
    );
}

#[test]
fn binder_refbase_calls_follow_each_objects_virtual_base_offset() {
    let _guard = TEST_LOCK.lock().unwrap();
    exercise_virtual_layout(0, 4);
    exercise_virtual_layout(0, 10);
}

#[test]
fn binder_refbase_offset_is_signed_for_a_secondary_interface() {
    let _guard = TEST_LOCK.lock().unwrap();
    exercise_virtual_layout(8, 2);
}

#[test]
fn direct_refbase_owner_does_not_read_a_virtual_table() {
    let _guard = TEST_LOCK.lock().unwrap();
    CALLS.lock().unwrap().clear();
    // 第一字并非 vptr，Direct 路径仍须能正确移交和释放引用。
    let mut storage = Box::new([0usize; 2]);
    let pointer = storage.as_mut_ptr().cast();
    let mut returned = CppStrongPointerReturn::uninitialized();
    unsafe { returned.write_pointer_for_foreign_return(pointer) };
    let owner =
        unsafe { OwnedStrongPointer::adopt_returned(&mut returned, retain, release) }.unwrap();
    assert_eq!(owner.pointer(), pointer);
    assert_eq!(owner.raw().pointer, pointer);
    drop(owner);
    let recorded = calls();
    assert_eq!(recorded.len(), 3);
    assert!(recorded.iter().all(|call| call.this == pointer as usize));
    assert_eq!(recorded[0].operation, Operation::Retain);
    assert_eq!(recorded[1].operation, Operation::Release);
    assert_eq!(recorded[2].operation, Operation::Release);
}

#[test]
fn null_binder_return_never_reads_a_virtual_table_or_changes_references() {
    let _guard = TEST_LOCK.lock().unwrap();
    CALLS.lock().unwrap().clear();
    let mut returned = CppStrongPointerReturn::uninitialized();
    unsafe { returned.write_pointer_for_foreign_return(std::ptr::null_mut()) };
    let owner = unsafe {
        OwnedStrongPointer::adopt_returned_as(
            &mut returned,
            RefBaseLayout::BinderVirtual,
            retain,
            release,
        )
    };
    assert!(owner.is_none());
    assert!(calls().is_empty());
}
