//! When changing relay selection, please verify if `docs/relay-selector.md` needs to be
//! updated as well.

mod constants;
mod error;
mod parsed_relays;
mod relay_selector;

// Re-exports
pub use error::Error;
pub use relay_selector::RelaySelector;
// TODO(markus): Obsolete?
pub use relay_selector::{
    NormalSelectedRelay, SelectedBridge, SelectedObfuscator, SelectedRelay, SelectorConfig,
};
