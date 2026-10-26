pub fn SvcExceptionTicks(
    syscall_number: u64,
    getpid_number: u64,
    ioctl_number: u64,
    default_ticks: u64,
    getpid_ticks: u64,
    ioctl_ticks: u64,
) -> u64 {
    if syscall_number == getpid_number {
        getpid_ticks
    } else if syscall_number == ioctl_number {
        ioctl_ticks
    } else {
        default_ticks
    }
}
pub fn GuestCounterValue(
    base: u64,
    instruction_count: u64,
    exception_ticks: u64,
    scale_by_core_frequency: bool,
    counter_frequency: u64,
    assumed_core_frequency: u64,
) -> u64 {
    let progress = if !scale_by_core_frequency || assumed_core_frequency == 0 {
        instruction_count as u128
    } else {
        (instruction_count as u128 * counter_frequency as u128) / assumed_core_frequency as u128
    };
    base.wrapping_add(progress as u64)
        .wrapping_add(exception_ticks)
}
