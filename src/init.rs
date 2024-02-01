use std::io::{ErrorKind, Write};

use crate::loader::load_module;
use anyhow::Result;
use rustix::fs::{chmodat, symlink, unlink, AtFlags, Mode};
use rustix::mount::fsconfig_create;
use rustix::{
    fd::AsFd,
    fs::{access, makedev, mkdir, mknodat, Access, FileType, CWD},
    mount::{
        fsconfig_create, fsmount, fsopen, move_mount, unmount, FsMountFlags, FsOpenFlags,
        MountAttrFlags, MoveMountFlags, UnmountFlags,
    },
};

struct AutoUmount {
    mountpoints: Vec<String>,
}

impl Drop for AutoUmount {
    fn drop(&mut self) {
        for mountpoint in self.mountpoints.iter().rev() {
            if let Err(e) = unmount(mountpoint.as_str(), UnmountFlags::DETACH) {
                log::error!("Cannot umount {}: {}", mountpoint, e)
            }
        }
    }
}

fn prepare_mount() -> AutoUmount {
    let mut mountpoints = vec![];

    // mount procfs
    let result = mkdir("/proc", Mode::from_raw_mode(0o755))
        .or_else(|err| match err.kind() {
            ErrorKind::AlreadyExists => Ok(()),
            _ => Err(err),
        })
        .and_then(|_| fsopen("proc", FsOpenFlags::FSOPEN_CLOEXEC))
        .and_then(|fd| fsconfig_create(fd.as_fd()).map(|_| fd))
        .and_then(|fd| {
            fsconfig_create(fd.as_fd())?;
            fsmount(
                fd.as_fd(),
                FsMountFlags::FSMOUNT_CLOEXEC,
                MountAttrFlags::empty(),
            )
        })
        .and_then(|fd| {
            move_mount(
                fd.as_fd(),
                "",
                CWD,
                "/proc",
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )
        });
    match result {
        Ok(_) => mountpoints.push("/proc".to_string()),
        Err(e) => log::error!("Cannot mount procfs: {:?}", e),
    }

    // mount sysfs
    let result = mkdir("/sys", Mode::from_raw_mode(0o755))
        .or_else(|err| match err.kind() {
            ErrorKind::AlreadyExists => Ok(()),
            _ => Err(err),
        })
        .and_then(|_| fsopen("sysfs", FsOpenFlags::FSOPEN_CLOEXEC))
        .and_then(|fd| fsconfig_create(fd.as_fd()).map(|_| fd))
        .and_then(|fd| {
            fsconfig_create(fd.as_fd())?;
            fsmount(
                fd.as_fd(),
                FsMountFlags::FSMOUNT_CLOEXEC,
                MountAttrFlags::empty(),
            )
        })
        .and_then(|fd| {
            move_mount(
                fd.as_fd(),
                "",
                CWD,
                "/sys",
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )
        });

    match result {
        Ok(_) => mountpoints.push("/sys".to_string()),
        Err(e) => log::error!("Cannot mount sysfs: {:?}", e),
    }

    AutoUmount { mountpoints }
}

fn setup_kmsg() {
    const KMSG: &str = "/dev/kmsg";
    let device = match access(KMSG, Access::EXISTS) {
        Ok(_) => KMSG,
        Err(_) => {
            // try to create it
            mknodat(
                CWD,
                "/kmsg",
                FileType::CharacterDevice,
                0o666.into(),
                makedev(1, 11),
            )
            .ok();
            "/kmsg"
        }
    };

    let _ = kernlog::init_with_device(device);
}

fn unlimit_kmsg() {
    // Disable kmsg rate limiting
    if let Ok(mut rate) = std::fs::File::options()
        .write(true)
        .open("/proc/sys/kernel/printk_devkmsg")
    {
        writeln!(rate, "on").ok();
    }
}

pub fn init() -> Result<()> {
    // Setup kernel log first
    setup_kmsg();

    log::info!("Hello, KernelSU!");

    // mount /proc and /sys to access kernel interface
    let _dontdrop = prepare_mount();

    // This relies on the fact that we have /proc mounted
    unlimit_kmsg();

    // insmod kernelsu module
    if let Err(e) = load_module("/kernelsu.ko") {
        log::error!("Cannot load kernelsu module: {}", e);
    }

    // And now we should prepare the real init to transfer control to it
    unlink("/init")?;

    let real_init = match access("/init.real", Access::EXISTS) {
        Ok(_) => "init.real",
        Err(_) => "/system/bin/init",
    };

    log::info!("init is {}", real_init);
    symlink(real_init, "/init")?;

    chmodat(
        CWD,
        "/init",
        Mode::from_raw_mode(0o755),
        AtFlags::SYMLINK_NOFOLLOW,
    )?;

    Ok(())
}
