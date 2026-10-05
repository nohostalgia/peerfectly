//! The packet device: a TUN interface, and nothing that outlives it.
//!
//! An implementation of [`tunnel::Packets`] over `/dev/net/tun`. Every rule
//! about which packets may pass is in `daemon::gateway` and `tunnel`; this
//! module moves bytes.
//!
//! # Not persistent, and that is the point
//!
//! The interface is made with `TUNSETIFF` and **never** `TUNSETPERSIST`, so the
//! kernel removes it when the last descriptor on it closes — when [`Tun`] is
//! dropped, when the daemon exits, and when it is killed. Every address, route
//! and per-interface resolver setting on it goes with it. A crash therefore
//! leaves nothing behind for a later start to find, which is the property
//! Windows needs a sweep of the registry to approach.
//!
//! # Why this is `unsafe`
//!
//! Naming the interface and setting its flags is one `ioctl` with an `ifreq`,
//! and neither `libc` nor `rustix` wraps it. That call, and filling the
//! structure it reads, are the whole `unsafe` surface of this crate. Reading and
//! writing packets afterwards goes through `rustix` on an [`OwnedFd`], which is
//! safe; the descriptor is opened by `rustix` too, so its ownership is never in
//! doubt.
//!
//! # What is not tested here
//!
//! Opening `/dev/net/tun` needs `CAP_NET_ADMIN`. The tests that do it are
//! `#[ignore]`d and run in the testbed, where the container has the capability
//! and the device; `VERIFICATION.md` records it.

#![allow(
    unsafe_code,
    reason = "TUNSETIFF has no safe wrapper; the unsafe surface is this one ioctl, confined to \
              this module as `route_table` confines Windows' IP Helper calls"
)]

use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd};

use async_trait::async_trait;
use rustix::fs::{Mode, OFlags};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tunnel::Packets;

/// The kernel's TUN device.
const DEVICE: &str = "/dev/net/tun";

/// The largest read: the most an IP packet can be. The link's MTU keeps what
/// arrives far smaller; a buffer sized to it would truncate silently if it did
/// not, and the gateway refuses anything past the MTU in any case.
const LARGEST: usize = 65_535;

/// A TUN interface, open.
pub struct Tun {
    /// The descriptor. The interface lives exactly as long as it does.
    fd: AsyncFd<OwnedFd>,
    /// What the kernel named it, which is what was asked for.
    name: String,
}

impl Tun {
    /// Makes the interface `name`, carrying bare IP packets.
    ///
    /// # Errors
    ///
    /// When the device cannot be opened — most often for want of
    /// `CAP_NET_ADMIN` — or the kernel refuses the name.
    pub fn open(name: &str) -> io::Result<Self> {
        let request = request_for(name)?;

        let fd = rustix::fs::open(
            DEVICE,
            OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|cause| {
            let cause = io::Error::from(cause);
            io::Error::new(cause.kind(), format!("opening {DEVICE}: {cause}"))
        })?;

        let mut request = request;
        // SAFETY: `fd` is an open descriptor on the TUN device, owned here, and
        // `request` is a fully initialised `ifreq` that lives across the call.
        // TUNSETIFF reads the name and flags from it and writes the name back;
        // it keeps no pointer into it after returning.
        let status = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &raw mut request) };
        if status < 0 {
            let cause = io::Error::last_os_error();
            return Err(io::Error::new(
                cause.kind(),
                format!("naming the interface {name}: {cause}"),
            ));
        }

        Ok(Self {
            fd: AsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE)?,
            name: name.to_owned(),
        })
    }

    /// What the interface is called.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The request TUNSETIFF reads: the name, and bare IP packets with no header.
fn request_for(name: &str) -> io::Result<libc::ifreq> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{name}` is not a name the kernel takes"),
        ));
    }
    // SAFETY: `ifreq` is plain data — arrays of integers and a union of
    // integers and pointers — for which all zeroes is a valid value.
    let mut request: libc::ifreq = unsafe { core::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    // `IFF_NO_PI`: no four-byte header before each packet, so a read is exactly
    // one IP packet — what `Packets` carries on every platform.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "both flags fit in the short the kernel reads"
    )]
    let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    request.ifr_ifru.ifru_flags = flags;
    Ok(request)
}

#[async_trait]
impl Packets for Tun {
    async fn deliver(&self, packet: &[u8]) -> io::Result<()> {
        let written = self
            .fd
            .async_io(Interest::WRITABLE, |fd| {
                rustix::io::write(fd, packet).map_err(io::Error::from)
            })
            .await?;
        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("the kernel took {written} of {} bytes", packet.len()),
            ));
        }
        Ok(())
    }

    async fn take(&self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0_u8; LARGEST];
        let read = self
            .fd
            .async_io(Interest::READABLE, |fd| {
                rustix::io::read(fd, &mut buffer).map_err(io::Error::from)
            })
            .await?;
        buffer.truncate(read);
        Ok(buffer)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The name the kernel is given is the name asked for, terminated, and a
    /// name it could not hold is refused before anything is opened.
    #[test]
    fn the_request_carries_the_name_and_bare_packets() {
        let request = request_for("peer0123456789a").unwrap();
        let named: Vec<u8> = request
            .ifr_name
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        assert_eq!(b"peer0123456789a".as_slice(), named.as_slice());
        // SAFETY: reading back the member this test wrote.
        let flags = i32::from(unsafe { request.ifr_ifru.ifru_flags });
        assert_eq!(libc::IFF_TUN | libc::IFF_NO_PI, flags);
        assert_eq!(0, flags & 0x0800, "never IFF_TAP: this carries IP, not Ethernet");

        for refused in ["", "peer0123456789ab", "a\0b"] {
            assert!(request_for(refused).is_err(), "`{refused:?}`");
        }
    }

    /// **Never persistent.** A persistent interface outlives the daemon, and
    /// with it every route and resolver setting on it: exactly what a crash must
    /// not leave behind.
    #[test]
    fn the_interface_is_never_made_persistent() {
        let code: String = include_str!("tun.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        assert!(!code.contains("TUNSETPERSIST"), "the interface must go with the descriptor");
        assert!(code.contains("TUNSETIFF"));
    }

    /// The interface exists while the device is held, and is gone once it is
    /// dropped. Needs `CAP_NET_ADMIN`: run in the testbed.
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN and /dev/net/tun: run in the testbed"]
    async fn the_interface_lives_exactly_as_long_as_the_device() {
        let name = "peerfectlytest00001";
        let tun = Tun::open(name).unwrap();
        assert!(std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
        assert_eq!(name, tun.name());
        drop(tun);
        assert!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists(), "gone with it");
    }
}
