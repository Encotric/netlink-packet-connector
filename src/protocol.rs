use std::{error::Error, fmt};

use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkHeader, NetlinkPayload,
    NetlinkSerializable,
};

/// Identity of a connecting process.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConnectorId {
    idx: u32,
    value: u32
}

/// The netlink connector protocol relies only on one message type.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConnectorMessage {
    id: ConnectorId,
    seq: u32,
    ack: u32,
    flags: u16,
    data: Vec<u8>,
}

impl ConnectorMessage {

    pub fn new(idx: u32, value: u32, seq: u32, ack: u32, flags: u16, data: Vec<u8>) -> Self {
        ConnectorMessage {
            id: ConnectorId { idx, value },
            seq,
            ack,
            flags,
            data,
        }
    }

    pub fn idx(&self) -> u32 {
        self.id.idx
    }

    pub fn value(&self) -> u32 {
        self.id.value
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    pub fn ack(&self) -> u32 {
        self.ack
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

// A custom error type for when deserialization fails. This is
// required because `NetlinkDeserializable::Error` must implement
// `std::error::Error`, so a simple `String` won't cut it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeserializeError(&'static str);

impl Error for DeserializeError {
    fn description(&self) -> &str {
        self.0
    }
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// NetlinkDeserializable implementation
impl NetlinkDeserializable for ConnectorMessage {
    type Error = DeserializeError;

    fn deserialize(
        _header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, Self::Error> {
        let idx: u32 = NativeEndian::read_u32(&payload[0..4]);
        let value: u32 = NativeEndian::read_u32(&payload[4..8]);
        let seq: u32 = NativeEndian::read_u32(&payload[8..12]);
        let ack: u32 = NativeEndian::read_u32(&payload[12..16]);
        let len: u16 = NativeEndian::read_u16(&payload[16..18]);
        let flags: u16 = NativeEndian::read_u16(&payload[18..20]);
        let data = payload[20..].to_vec();

        if data.len() as u16 != len {
            return Err(DeserializeError("Invalid data length"));
        }

        Ok(ConnectorMessage {
            id: ConnectorId { idx, value },
            seq,
            ack,
            flags,
            data,
        })
    }
}

// NetlinkSerializable implementation
impl NetlinkSerializable for ConnectorMessage {
    fn message_type(&self) -> u16 {
        0
    }

    fn buffer_len(&self) -> usize {
        20 + self.data.len()
    }

    fn serialize(&self, buffer: &mut [u8]) {
        NativeEndian::write_u32(&mut buffer[0..4], self.id.idx);
        NativeEndian::write_u32(&mut buffer[4..8], self.id.value);
        NativeEndian::write_u32(&mut buffer[8..12], self.seq);
        NativeEndian::write_u32(&mut buffer[12..16], self.ack);
        NativeEndian::write_u16(&mut buffer[16..18], self.data.len() as u16);
        NativeEndian::write_u16(&mut buffer[18..20], self.flags);
        buffer[20..].copy_from_slice(&self.data);
    }
}

// It can be convenient to be able to create a NetlinkMessage directly
// from a PingPongMessage. Since NetlinkMessage<T> already implements
// From<NetlinkPayload<T>>, we just need to implement
// From<NetlinkPayload<PingPongMessage>> for this to work.
impl From<ConnectorMessage> for NetlinkPayload<ConnectorMessage> {
    fn from(message: ConnectorMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
