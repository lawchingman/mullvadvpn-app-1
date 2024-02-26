//! TODO(markus): Document this

use mullvad_types::relay_constraints::MissingCustomBridgeSettings;

#[derive(err_derive::Error, Debug)]
#[error(no_from)]
pub enum Error {
    #[error(display = "Failed to open relay cache file")]
    OpenRelayCache(#[error(source)] std::io::Error),

    #[error(display = "Failed to write relay cache file to disk")]
    WriteRelayCache(#[error(source)] std::io::Error),

    #[error(display = "No relays matching current constraints")]
    NoRelay,

    #[error(display = "No bridges matching current constraints")]
    NoBridge,

    #[error(display = "No obfuscators matching current constraints")]
    NoObfuscator,

    #[error(display = "Failure in serialization of the relay list")]
    Serialize(#[error(source)] serde_json::Error),

    #[error(display = "Downloader already shut down")]
    DownloaderShutDown,

    #[error(display = "Invalid bridge settings")]
    InvalidBridgeSettings(#[error(source)] MissingCustomBridgeSettings),
}
