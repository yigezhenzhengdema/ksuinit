use goblin::elf::{section_header, sym::Sym, Elf};
use scroll::{ctx::SizeWith, Pwrite};
use std::collections::HashMap;

use anyhow::{Context, Result};
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

    let kallsyms = "/proc/kallsyms";
    let mut map = HashMap::new();
    let content = fs::read_to_string(kallsyms)?;
    for line in content.lines() {
        let splits = line.split_whitespace().collect::<Vec<&str>>();
        if splits.len() < 3 {
            continue;
        }

        let symbol = splits[2];
        let addr_str = splits[0];
        let addr = u64::from_str_radix(addr_str, 16)?;

        map.insert(symbol.to_string(), addr);
    }
    Ok(map)
}

pub fn load_module(path: &str) -> Result<()> {
    let mut buffer = fs::read(path).with_context(|| format!("Cannot read file: {path}"))?;
    let elf = Elf::parse(&buffer)?;

    let missing_symbols = vec![
        "kallsyms_lookup_name",
        "register_kprobe",
        "dentry_path_raw",
        "kern_path",
        "path_put",
        "unregister_kprobe",
        "security_add_hooks",
        "groups_free",
        "groups_alloc",
        "groups_sort",
        "set_groups",
        "path_umount",
        "init_nsproxy",
        "security_hook_heads",
        "filp_open",
        "kernel_read",
        "kernel_write",
        "strncpy_from_user_nofault",
        "security_secid_to_secctx",
        "security_secctx_to_secid",
        "selinux_state",
        "selinux_blob_sizes",
        "symtab_search",
        "symtab_insert",
        "ebitmap_set_bit",
        "ebitmap_get_bit",
        "avtab_search_node",
        "avtab_search_node_next",
        "avtab_insert_nonunique",
        "policydb_filenametr_search",
        "__hashtab_insert",
        "avc_ss_reset",
        "selnl_notify_policyload",
        "selinux_status_update_policyload",
    ];

    let kernel_symbols = parse_kallsyms()?;

    let mut modifications = Vec::new();
    for (index, mut sym) in elf.syms.iter().enumerate() {
        let Some(name) = elf.strtab.get_at(sym.st_name) else {
            continue;
        };

        if missing_symbols.contains(&name) {
            let offset = elf.syms.offset() + index * Sym::size_with(elf.syms.ctx());
            let real_addr = kernel_symbols
                .get(name).ok_or(anyhow::anyhow!("Cannot found symbol: {}", &name))?;
            sym.st_shndx = section_header::SHN_ABS as usize;
            sym.st_value = *real_addr;
            modifications.push((sym, offset));
        }
    }

    anyhow::ensure!(
        modifications.len() == missing_symbols.len(),
        "Missing symbols!"
    );

    let ctx = *elf.syms.ctx();
    for ele in modifications {
        buffer.pwrite_with(ele.0, ele.1, ctx)?;
    }

    nix::kmod::init_module(&buffer, &std::ffi::CString::new("").unwrap())
        .with_context(|| "Cannot load module")?;

    Ok(())
}
