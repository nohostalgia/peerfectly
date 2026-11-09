//! The frames this project's sessions carry over convesso, and how a frame
//! too large for its receiver travels in parts: no input, no output, and no
//! operating system, so a computer's binding (`transport-convesso`) and a
//! microcontroller member speak them alike.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod fragment;
pub mod frame;
pub mod parts;
