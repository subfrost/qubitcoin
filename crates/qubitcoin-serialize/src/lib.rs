//! qubitcoin-serialize: Serialization framework for Qubitcoin.
//!
//! Maps to: src/serialize.h, src/streams.h
//!
//! Provides:
//! - `Encodable`/`Decodable` traits (port of Bitcoin Core's SERIALIZE_METHODS)
//! - `CompactSize` encoding/decoding
//! - `VarInt` encoding/decoding
//! - `DataStream` in-memory buffer

pub mod compact_size;
pub mod data_stream;
pub mod encode;
pub mod varint;

pub use compact_size::{compact_size_len, read_compact_size, write_compact_size};
pub use data_stream::DataStream;
pub use encode::{
    decode_vec, deserialize, encode_vec, serialize, Decodable, Encodable, Error, MAX_SIZE,
};
pub use varint::{read_varint, varint_len, write_varint};
