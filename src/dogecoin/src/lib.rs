use bitcoin::{
    consensus::{encode, Decodable, Encodable},
    VarInt,
};
use bitcoin_io::{Error, Read, Write};

pub mod amount;
pub mod block;
pub mod canister;
pub mod chainparams;
pub mod internal_macros;
pub mod jsonrpc;
pub mod opcodes;
pub mod p2p;
pub mod script;
pub mod sighash;
pub mod transaction;

pub extern crate hex;

pub fn consensus_encode_vec<T, W>(vv: &[T], w: &mut W) -> Result<usize, Error>
where
    T: Encodable,
    W: Write + ?Sized,
{
    let mut len = 0;
    VarInt::from(vv.len()).consensus_encode(w)?;
    for v in vv.iter() {
        len += v.consensus_encode(w)?;
    }
    Ok(len)
}

pub fn consensus_decode_from_vec<T, R>(r: &mut R) -> Result<Vec<T>, encode::Error>
where
    T: Decodable,
    R: Read + ?Sized,
{
    let cap: VarInt = Decodable::consensus_decode(r)?;
    let cap = cap.0 as usize;
    let mut vv = Vec::with_capacity(cap);
    for _ in 0..cap {
        vv.push(Decodable::consensus_decode_from_finite_reader(r)?);
    }
    Ok(vv)
}

pub fn err_string(err: impl std::fmt::Display) -> String {
    err.to_string()
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Vec_<T>(Vec<T>);

impl<T> From<Vec<T>> for Vec_<T> {
    fn from(vec: Vec<T>) -> Self {
        Vec_(vec)
    }
}

impl<T> AsRef<Vec<T>> for Vec_<T> {
    fn as_ref(&self) -> &Vec<T> {
        &self.0
    }
}

macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec_<$type> {
            #[inline]
            fn consensus_encode<W: Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, bitcoin_io::Error> {
                let mut len = 0;
                len += VarInt(self.0.len() as u64).consensus_encode(w)?;
                for c in self.0.iter() {
                    len += c.consensus_encode(w)?;
                }
                Ok(len)
            }
        }

        impl Decodable for Vec_<$type> {
            #[inline]
            fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<Self, encode::Error> {
                let len = VarInt::consensus_decode_from_finite_reader(r)?.0;
                // Do not allocate upfront more items than if the sequence of type
                // occupied roughly quarter a block. This should never be the case
                // for normal data, but even if that's not true - `push` will just
                // reallocate.
                // Note: OOM protection relies on reader eventually running out of
                // data to feed us.
                let max_capacity =
                    bitcoin::consensus::encode::MAX_VEC_SIZE / 4 / std::mem::size_of::<$type>();
                let mut ret = Vec::with_capacity(core::cmp::min(len as usize, max_capacity));
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode_from_finite_reader(r)?);
                }
                Ok(Vec_(ret))
            }
        }
    };
}
impl_vec!(block::BlockHash);
impl_vec!(block::BlockHeader);
// impl_vec!(p2p::message_filter::FilterHash);
// impl_vec!(p2p::message_filter::FilterHeader);
impl_vec!(block::TxMerkleNode);
impl_vec!(transaction::Transaction);
impl_vec!(transaction::TxOut);
impl_vec!(transaction::TxIn);

#[cfg(feature = "std")]
impl_vec!(p2p::message_blockdata::Inventory);
#[cfg(feature = "std")]
impl_vec!((u32, p2p::address::Address));
#[cfg(feature = "std")]
impl_vec!(p2p::address::AddrV2Message);
