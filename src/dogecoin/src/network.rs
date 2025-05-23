use bitcoin::p2p::Magic;
use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Dogecoin,
    Testnet,
    Regtest,
}

impl Network {
    const fn as_display_str(self) -> &'static str {
        match self {
            Network::Dogecoin => "dogecoin",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        }
    }

    pub fn magic(self) -> Magic {
        match self {
            Network::Dogecoin => Magic::from_bytes([0xC0, 0xC0, 0xC0, 0xC0]),
            Network::Testnet => Magic::from_bytes([0xFC, 0xC1, 0xB7, 0xDC]),
            Network::Regtest => Magic::from_bytes([0xFA, 0xBF, 0xB5, 0xDA]),
        }
    }
}

impl FromStr for Network {
    type Err = ParseNetworkError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dogecoin" => Ok(Network::Dogecoin),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(ParseNetworkError(s.to_owned())),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.as_display_str())
    }
}

/// An error in parsing network string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseNetworkError(String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        bitcoin_internals::write_err!(f, "failed to parse {} as network", self.0; self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
