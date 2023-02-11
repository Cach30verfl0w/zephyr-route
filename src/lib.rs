#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::error::Error;

#[cfg(test)]
#[path = "../test/mod.rs"]
pub mod test;

#[cfg(feature = "bgp")]
pub mod bgp;

pub mod error;
pub mod io;

if_std! {
    pub type Result<T> = std::result::Result<T, Error>;
}

if_no_std! {
    pub type Result<T> = core::result::Result<T, Error>;
}

#[cfg(all(not(feature = "bgp"), not(feature = "ospf")))]
compile_error!("You didn't compiled any routing protocol with this library. Please use minimal one of these protocols: BGP or OSPF");

#[cfg(all(not(feature = "bgp"), feature = "bgp_route_refresh"))]
compile_error!("You should enable the BGP feature to use the BGP Route Refresh Capability feature!");

#[cfg(all(not(feature = "bgp"), feature = "bgp_multiprotocol"))]
compile_error!("You should enable the BGP feature to use the BGP Multi-protocol Extensions feature!");

/// This macro is just used by the library to insert logging calls, if you enable the log feature.
/// All log calls are using the log create of Rust.
#[macro_export]
macro_rules! if_log {
    ($item: expr) => {
        #[cfg(feature = "log")]
        $item
    };
}

/// This macro is just used by the library to identify, if the std feature is enabled.
#[macro_export]
macro_rules! if_std {
    ($item: item) => {
        #[cfg(feature = "std")]
        $item
    };
}

/// This macro is just used by the library to identify, if the std feature isn't enabled.
#[macro_export]
macro_rules! if_no_std {
    ($item: item) => {
        #[cfg(not(feature = "std"))]
        $item
    };
}
