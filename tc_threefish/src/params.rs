#[cfg(feature = "alloc")]
mod threefish_params_owned;
mod threefish_params_ref;

#[cfg(feature = "alloc")]
pub use threefish_params_owned::ThreefishParamsOwned;
pub use threefish_params_ref::ThreefishParamsRef;
