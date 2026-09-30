#[cfg(feature = "alloc")]
mod rc2_params_owned;
mod rc2_params_ref;
#[cfg(feature = "alloc")]
mod rc5_params_owned;
mod rc5_params_ref;

#[cfg(feature = "alloc")]
pub use rc2_params_owned::Rc2ParamsOwned;
pub use rc2_params_ref::Rc2ParamsRef;
#[cfg(feature = "alloc")]
pub use rc5_params_owned::Rc5ParamsOwned;
pub use rc5_params_ref::Rc5ParamsRef;
