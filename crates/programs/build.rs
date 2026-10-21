//! Gives the Windows programs their icon.
//!
//! The icon is `deploy/windows/peerfectly.ico` (`branding/README.md`), and is
//! linked into each program as a resource: Explorer, the Start menu and the
//! list of installed apps show it.
//!
//! The linker takes a compiled resource file as it is, so this writes one
//! itself, with no resource compiler and no added crate. A `.res` file is a
//! list of entries; an icon is one entry per image, and one more naming them.

use std::path::PathBuf;

/// The icon, from this crate's directory.
const ICON: &str = "../../deploy/windows/peerfectly.ico";
/// One image of an icon.
const RT_ICON: u16 = 3;
/// The entry that names an icon's images.
const RT_GROUP_ICON: u16 = 14;
/// Movable and discardable, as resource compilers mark icon images.
const IMAGE_FLAGS: u16 = 0x1010;
/// Movable, pure and discardable, as resource compilers mark the group.
const GROUP_FLAGS: u16 = 0x1030;

fn main() {
    println!("cargo:rerun-if-changed={ICON}");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "msvc");
    if !(windows && msvc) {
        return;
    }
    let ico = std::fs::read(ICON).expect("the icon is in the repository");
    let compiled = resources(&ico).expect("the icon is a well-formed .ico");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("peerfectly.res");
    std::fs::write(&out, compiled).expect("OUT_DIR can be written");
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

/// The `.res` file holding `ico` as the programs' icon, or `None` when `ico`
/// is not a well-formed icon file.
fn resources(ico: &[u8]) -> Option<Vec<u8>> {
    let count = u16_at(ico, 4)?;
    let mut compiled = Vec::new();
    // A `.res` file starts with an empty entry.
    entry(&mut compiled, 0, 0, 0, &[]);
    // The group: the directory of the `.ico`, with each image's place in the
    // file replaced by the id of its entry.
    let mut group = vec![0, 0, 1, 0];
    group.extend_from_slice(&count.to_le_bytes());
    for index in 0..count {
        let at = usize::from(index).checked_mul(16)?.checked_add(6)?;
        let header = ico.get(at..at.checked_add(16)?)?;
        let size = usize::try_from(u32_at(header, 8)?).ok()?;
        let offset = usize::try_from(u32_at(header, 12)?).ok()?;
        let image = ico.get(offset..offset.checked_add(size)?)?;
        let id = index.checked_add(1)?;
        entry(&mut compiled, RT_ICON, id, IMAGE_FLAGS, image);
        group.extend_from_slice(header.get(..12)?);
        group.extend_from_slice(&id.to_le_bytes());
    }
    entry(&mut compiled, RT_GROUP_ICON, 1, GROUP_FLAGS, &group);
    Some(compiled)
}

/// Appends one entry, of type `kind` and numeric name `name`, padded to four
/// bytes as the format wants.
fn entry(compiled: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    let size = u32::try_from(data.len()).expect("an icon image is far below 4 GiB");
    compiled.extend_from_slice(&size.to_le_bytes());
    // The header is 32 bytes: both names are numeric, so nothing varies.
    compiled.extend_from_slice(&32u32.to_le_bytes());
    for half in [0xFFFF, kind, 0xFFFF, name] {
        compiled.extend_from_slice(&half.to_le_bytes());
    }
    compiled.extend_from_slice(&0u32.to_le_bytes()); // data version
    compiled.extend_from_slice(&flags.to_le_bytes());
    compiled.extend_from_slice(&0u16.to_le_bytes()); // language: neutral
    compiled.extend_from_slice(&0u32.to_le_bytes()); // version
    compiled.extend_from_slice(&0u32.to_le_bytes()); // characteristics
    compiled.extend_from_slice(data);
    while !compiled.len().is_multiple_of(4) {
        compiled.push(0);
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let pair = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(pair.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let quad = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(quad.try_into().ok()?))
}
