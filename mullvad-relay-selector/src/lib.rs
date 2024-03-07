//! When changing relay selection, please verify if `docs/relay-selector.md` needs to be
//! updated as well.

mod constants;
mod error;
mod parsed_relays;
mod relay_selector;

// Re-exports
pub use error::Error;
pub use relay_selector::RelaySelector;
pub use relay_selector::{GetRelay, SelectedBridge, SelectedObfuscator, SelectorConfig};
