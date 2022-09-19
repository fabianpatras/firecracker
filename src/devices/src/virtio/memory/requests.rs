// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::ByteValued;

// types of requests for the `guest-request` virtq
pub const VIRTIO_MEM_REQ_PLUG: u16 = 0;
pub const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
pub const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
pub const VIRTIO_MEM_REQ_STATE: u16 = 3;

// types of responses for the `guest-request` virtq requests
pub const VIRTIO_MEM_RESP_ACK: u16 = 0;
pub const VIRTIO_MEM_RESP_NACK: u16 = 1;
pub const VIRTIO_MEM_RESP_BUSY: u16 = 2;
pub const VIRTIO_MEM_RESP_ERROR: u16 = 3;

/// Virtio Standard 1.2 defines the following struct for guest
/// request:
///
/// ```
/// struct virtio_mem_req {
///     le16 type;
///     le16 padding[3];
///     union {
///         struct virtio_mem_req_plug plug;
///         struct virtio_mem_req_unplug unplug;
///         struct virtio_mem_req_state state;
///     } u;
/// }
/// ```
///
/// but every one of those `struct` from the union
/// has the following structure:
///
/// ```
/// struct virtio_mem_req_{plug, unplug, state} {
///     le64 addr;
///     le16 nb_blocks;
///     le16 padding[3];
/// }
/// ```
///
/// so we can bypass using unions (which are unsafe) by using
/// all the common fields directy in out request structure
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct MemoryRequest {
    pub req_type: u16,
    _padding: [u16; 3],
    pub addr: u64,
    pub nb_blocks: u16,
    _padding2: [u16; 3],
}

// Safe because MemoryRequest only contains plain data.
unsafe impl ByteValued for MemoryRequest {}

// impl fmt::Debug for MemoryRequest {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "MemoryRequest [
//             req_type: [{}],
//             _padding: [{:?}],
//             addr:     [{:#x}],
//             nb_blocks:[{}],
//             _padding2:[{:?}]
//         ]",
//             self.req_type, self._padding, self.addr, self.nb_blocks, self._padding2,
//         )
//     }
// }

// padding required by the specs
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct MemoryResponse {
    pub resp_type: u16,
    _padding: [u16; 3],
    pub state_type: u16,
}

// Safe because MemoryRequest only contains plain data.
unsafe impl ByteValued for MemoryResponse {}

#[derive(Clone)]
pub struct MemoryRequestPlug {
    pub addr: u64,
    pub nb_blocks: u16,
}

#[derive(Clone)]
pub struct MemoryRequestUnplug {
    pub addr: u64,
    pub nb_blocks: u16,
}

#[derive(Clone)]
pub struct MemoryRequestState {
    pub addr: u64,
    pub nb_blocks: u16,
}

/// safe implementation to work around using unions inside `MemoryRequest`
impl MemoryRequest {
    pub fn is_plug(&self) -> bool {
        self.req_type == VIRTIO_MEM_REQ_PLUG
    }

    pub fn is_unplug(&self) -> bool {
        self.req_type == VIRTIO_MEM_REQ_UNPLUG
    }

    pub fn is_unplug_all(&self) -> bool {
        self.req_type == VIRTIO_MEM_REQ_UNPLUG_ALL
    }

    pub fn is_state(&self) -> bool {
        self.req_type == VIRTIO_MEM_REQ_STATE
    }

    /// caller must ensure the request is plug by usign `is_plug` first
    pub fn plug_request(&self) -> MemoryRequestPlug {
        MemoryRequestPlug {
            addr: self.addr,
            nb_blocks: self.nb_blocks,
        }
    }

    /// caller must ensure the request is plug by usign `is_unplug` first
    pub fn unplug_request(&self) -> MemoryRequestUnplug {
        MemoryRequestUnplug {
            addr: self.addr,
            nb_blocks: self.nb_blocks,
        }
    }

    /// caller must ensure the request is plug by usign `is_state` first
    pub fn state_request(&self) -> MemoryRequestState {
        MemoryRequestState {
            addr: self.addr,
            nb_blocks: self.nb_blocks,
        }
    }
}

impl MemoryResponse {
    pub fn new() -> Self {
        MemoryResponse {
            ..Default::default()
        }
    }
    pub fn ack(&mut self) -> Self {
        self.resp_type = VIRTIO_MEM_RESP_ACK;
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // impl Default for MemoryRequest {
    //     fn default() -> Self {
    //         MemoryRequest {
    //             req_type: 0,
    //             _padding: [0u16; 3],
    //             addr: 0,
    //             nb_blocks: 0,
    //             _padding2: [0u16; 3],
    //         }
    //     }
    // }

    #[test]
    fn test_basic_checks() {
        let plug_req = MemoryRequest {
            req_type: VIRTIO_MEM_REQ_PLUG,
            addr: 0x1000,
            nb_blocks: 132,
            ..Default::default()
        };

        assert!(plug_req.is_plug());
        assert_eq!(plug_req.plug_request().addr, plug_req.addr);
        assert_eq!(plug_req.plug_request().nb_blocks, plug_req.nb_blocks);

        let unplug_req = MemoryRequest {
            req_type: VIRTIO_MEM_REQ_UNPLUG,
            addr: 0x2000,
            nb_blocks: 61,
            ..Default::default()
        };

        assert!(unplug_req.is_unplug());
        assert_eq!(unplug_req.unplug_request().addr, unplug_req.addr);
        assert_eq!(unplug_req.unplug_request().nb_blocks, unplug_req.nb_blocks);

        let unplug_all_req = MemoryRequest {
            req_type: VIRTIO_MEM_REQ_UNPLUG_ALL,
            addr: 0xDEAD,
            nb_blocks: 1234,
            ..Default::default()
        };

        assert!(unplug_all_req.is_unplug_all());

        let state_req = MemoryRequest {
            req_type: VIRTIO_MEM_REQ_STATE,
            addr: 0xBEEF,
            nb_blocks: 4321,
            ..Default::default()
        };

        assert!(state_req.is_state());
        assert_eq!(state_req.state_request().addr, state_req.addr);
        assert_eq!(state_req.state_request().nb_blocks, state_req.nb_blocks);

        let broken_req = MemoryRequest {
            req_type: 44823,
            addr: 0x15552334,
            nb_blocks: 11110,
            ..Default::default()
        };

        assert!(!broken_req.is_plug());
        assert!(!broken_req.is_unplug());
        assert!(!broken_req.is_unplug_all());
        assert!(!broken_req.is_state());
    }
}
