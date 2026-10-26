# 内核陀螺仪输出

SurfaceFlinger 生产路径使用 `KernelSensorController`，通过
`KernelDriver::ConfigureGyroEvent` 调用模块 `0x1003f`，不在 SF 内安装旧的
sensorservice 用户态 hook。host 保留 `AddRotation`、`SetAngularVelocity` 和轴映射接口。
角速度仍为度/秒，控制器转换为弧度/秒并叠加到物理 X/Y 输入，保留 Z。

内核配置没有超时，持续生效直到关闭、替换或 Once 消费。通用控制器默认同样不超时：

```rust,ignore
let sensor = KernelSensorController::new(driver, MonotonicClock);
// 或由调用方选择自己的超时策略：
let sensor = KernelSensorController::WithIdleTimeout(
    driver, MonotonicClock, Some(Duration::from_millis(100)),
);
```

`None` 不启动看门狗。指定时长后，用户态 `gyro-watchdog` 每 33 ms 检查最后一次
成功写入时间，并在过期时调用关闭接口。当前 host 自瞄在组装处显式选用 100 ms。
线程入口使用 `SCHED_OTHER`、nice=0；检查、发布与停止共用锁，旧超时不会清掉新写入。
关闭失败会保留待关闭状态并重试。它不是硬实时计时器，也不能在所属进程被停止或崩溃后运行。

`Start` 先关闭旧值并检查模块是否支持接口；写零、`Stop` 和正常 Drop 都主动关闭输出。
`Stop` 等待看门狗退出，错误会向调用方传播，Drop 仅作尽力清理。不支持接口的旧内核
会报告启动错误，不回退到旧 hook。通用旧控制器保留供已有调用者及回归测试使用。

模块配置是全局的，控制器应由单个运行时持有；多个实例会覆盖/关闭彼此的输出。
当前内核限定 system_server 发送、104 字节事件、handle 0x29、type 4，且不区分接收应用。
这些条件需要在具体 ROM 上确认。

单测覆盖角度/角速度换算、轴映射、持久模式、可选超时与刷新、真实看门狗线程、
写入失败、关闭重试、生命周期和 ABI 无超时参数；QEMU 与真实 Android 验证范围
见内核仓库 `docs/gyro-event.md` 及本轮验证报告。
