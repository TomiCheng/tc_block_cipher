#[cfg(feature = "alloc")]
mod gost28147_params_owned;
mod gost28147_params_ref;

#[cfg(feature = "alloc")]
pub use gost28147_params_owned::Gost28147ParamsOwned;
pub use gost28147_params_ref::Gost28147ParamsRef;
