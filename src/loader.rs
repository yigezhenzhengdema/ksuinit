use anyhow::{anyhow, Context, Result};
use goblin::elf::{section_header, sym::Sym, Elf};
use rustix::{cstr, runtime::init_module};
use scroll::{ctx::SizeWith, Pwrite};
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs;

const KPTR_RESTRICT: &str = "/proc/sys/kernel/kptr_restrict";

struct Kptr {
    value: String,
}

impl Kptr {
    pub fn new() -> Result<Self> {
        let value = fs::read_to_string(KPTR_RESTRICT)?;
        fs::write(KPTR_RESTRICT, "1")?;
        Ok(Kptr { value })
    }
}

impl Drop for Kptr {
    fn drop(&mut self) {
        let _ = fs::write(KPTR_RESTRICT, self.value.as_bytes());
    }
}

fn parse_kallsyms() -> Result<HashMap<String, u64>> {
    let _dontdrop = Kptr::new()?;

    let allsyms = fs::read_to_string("/proc/kallsyms")?
        .lines()
        .map(|line| line.split_whitespace())
        .filter_map(|mut splits| {
            splits
                .nth(0)
                .and_then(|addr| u64::from_str_radix(addr, 16).ok())
                .and_then(|addr| splits.nth(1).and_then(|symbol| Some((symbol, addr))))
        })
        .map(|(symbol, addr)| {
            (
                symbol
                    .find(['$', '.'])
                    .map_or(symbol, |pos| &symbol[0..pos])
                    .to_owned(),
                addr,
            )
        })
        .collect::<HashMap<_, _>>();

    Ok(allsyms)
}

pub fn load_module(path: &str) -> Result<()> {
    let mut buffer = fs::read(path).with_context(|| format!("Cannot read file: {path}"))?;
    let elf = Elf::parse(&buffer)?;

    let kernel_symbols = parse_kallsyms()?;

    let mut modifications = Vec::new();
    for (index, mut sym) in elf.syms.iter().enumerate() {
        if index == 0 {
            continue;
        }

        if sym.st_shndx != section_header::SHN_UNDEF as usize {
            continue;
        }

        let Some(name) = elf.strtab.get_at(sym.st_name) else {
            continue;
        };

        let offset = elf.syms.offset() + index * Sym::size_with(elf.syms.ctx());
        let Some(real_addr) = kernel_symbols.get(name) else {
            log::warn!("Cannot found symbol: {}", &name);
            continue;
        };
        sym.st_shndx = section_header::SHN_ABS as usize;
        sym.st_value = *real_addr;
        modifications.push((sym, offset));
    }

    let ctx = *elf.syms.ctx();
    for ele in modifications {
        buffer.pwrite_with(ele.0, ele.1, ctx)?;
    }
    unsafe {
        let errno = init_module(
            buffer.as_ptr() as *const c_void,
            buffer.len() as u32,
            cstr!(""),
        ).raw_os_error();
        if errno != 0 {
            return Err(anyhow!("Cannot load module"));
        }
    }
    Ok(())
}
