use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
};

use std::io::Write;

use anyhow::Result;

use crate::loader::load_module;

struct AutoUmount {
    mountpoints: Vec<String>,
}

impl Drop for AutoUmount {
    fn drop(&mut self) {
        for mountpoint in self.mountpoints.iter().rev() {
            if let Err(e) = nix::mount::umount(mountpoint.as_str()) {
                log::error!("Cannot umount {}: {}", mountpoint, e)
            }
        }
    }
}

fn prepare_mount() -> AutoUmount {
    let mut mountpoints = vec![];

    let _ = std::fs::DirBuilder::new().mode(0o755).create("/proc");
    let result = nix::mount::mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    );

    if result.is_ok() {
        mountpoints.push("/proc".to_string());
    }

    // mount sysfs
    let _ = std::fs::DirBuilder::new().mode(0o755).create("/sys");
    let result = nix::mount::mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    );

    if result.is_ok() {
        mountpoints.push("/sys".to_string());
    }

    AutoUmount { mountpoints }
}

fn setup_kmsg() {
    const KMSG: &str = "/dev/kmsg";
    let mut device = KMSG;
    if !Path::new(KMSG).exists() {
        // we can do nothing if mkdnod failed
        let _ = nix::sys::stat::mknod(
            "/kmsg",
            nix::sys::stat::SFlag::S_IFCHR,
            nix::sys::stat::Mode::from_bits(0o666).unwrap(),
            libc::makedev(1, 11),
        );
        device = "/kmsg";
    }

    // Disable kmsg rate limiting
    if let Ok(mut rate) = std::fs::File::options()
        .write(true)
        .open("/proc/sys/kernel/printk_devkmsg")
    {
        writeln!(rate, "on").ok();
    }

    let _ = kernlog::init_with_device(device);
}

pub fn init() -> Result<()> {
    // mount /proc and /sys to access kernel interface
    let _dontdrop = prepare_mount();

    setup_kmsg();

    log::info!("Hello, KernelSU!");

    // insmod kernelsu module
    if let Err(e) = load_module("/kernelsu.ko") {
        log::error!("Cannot load kernelsu module: {}", e);
    }

    // And now we should prepare the real init to transfer control to it
    let _ = nix::unistd::unlink("/init");

    let mut real_init = "init.real";
    if !Path::new(real_init).exists() {
        // no real init, these is the GKI ramdisk, the real init is in /system/bin/init
        real_init = "/system/bin/init";
    }

    log::info!("init is {}", real_init);
    nix::unistd::symlinkat(real_init, None, "/init")?;

    let _ = std::fs::set_permissions("/init", std::fs::Permissions::from_mode(0o755));

    Ok(())
}
