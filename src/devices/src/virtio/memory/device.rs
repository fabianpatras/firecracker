// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::convert::TryInto;
use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use logger::{debug, error, info};
use utils::eventfd::EventFd;
use utils::get_page_size;
use virtio_gen::virtio_blk::VIRTIO_F_VERSION_1;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap, MemoryBlockTracker};

// use crate::virtio::memory::MemoryResponse;
use crate::virtio::memory::{
    Error as MemoryError, MemoryRequest, MemoryResponse, GUEST_REQUESTS_INDEX, QUEUE_SIZE,
    VIRTIO_MEM_REQ_PLUG,
};
use crate::virtio::{
    ActivateResult, DeviceState, IrqTrigger, IrqType, Queue, VirtioDevice, TYPE_MEMORY,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConfigSpace {
    pub block_size: u64,
    pub node_id: u16,
    _padding: [u8; 6],
    pub addr: u64,
    pub region_size: u64,
    pub usable_region_size: u64,
    pub plugged_size: u64,
    pub requested_size: u64,
}

// Safe because ConfigSpace only contains plain data.
unsafe impl ByteValued for ConfigSpace {}

// Virtio memory device.
pub struct Memory {
    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) config_space: ConfigSpace,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: [Queue; 1],
    pub(crate) queue_evts: [EventFd; 1],
    pub(crate) device_state: DeviceState,
    pub(crate) irq_trigger: IrqTrigger,

    // Implementation specific fields.
    pub(crate) id: String,
    addr_is_set: bool,
    block_tracker: Option<Arc<Mutex<MemoryBlockTracker>>>,
}

impl Memory {
    pub fn new(
        block_size: u64,
        node_id: Option<u16>,
        region_size: u64,
        requested_size: u64,
        id: String,
    ) -> Result<Memory, MemoryError> {
        // the way this device will handle hot(un)plugs requires the block size
        // to be a multiple of the host page size
        //
        // memory device is only available for 64 bit platforms
        let page_size: u64 = get_page_size().map_err(MemoryError::PageSize)? as u64;

        if block_size == 0 {
            return Err(MemoryError::BlockSizeIsZero);
        }

        if block_size % page_size != 0 {
            return Err(MemoryError::BlockSizeNotMultipleOfPageSize(page_size));
        }

        // virtio-mem spec requirement
        if !block_size.is_power_of_two() {
            return Err(MemoryError::BlockSizeNotPowerOf2);
        }

        // virtio-mem spec requirement
        if region_size % block_size != 0 {
            return Err(MemoryError::SizeNotMultipleOfBlockSize);
        }

        if requested_size % block_size != 0 {
            return Err(MemoryError::SizeNotMultipleOfBlockSize);
        }

        // TODO: move me when implementing runtime API to change `requested_size`
        // let usable_region_size: u64 = std::cmp::min(region_size, 2 * requested_size);

        if let Some(node_id) = node_id {
            todo!("Node id feature unimplemented [{}]", node_id);
        }

        let avail_features = 1u64 << VIRTIO_F_VERSION_1;

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(MemoryError::EventFd)?];

        info!(
            "Memory::new({}, {:?}, {}, {})",
            block_size, node_id, region_size, id
        );

        Ok(Memory {
            avail_features,
            acked_features: 0u64,
            addr_is_set: false,
            config_space: ConfigSpace {
                block_size,
                node_id: node_id.unwrap_or_default(),
                _padding: [0u8; 6],
                addr: 0u64,
                region_size,
                usable_region_size: region_size,
                plugged_size: 0u64,
                requested_size,
            },
            id,
            irq_trigger: IrqTrigger::new().map_err(MemoryError::EventFd)?,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(MemoryError::EventFd)?,
            queues: [Queue::new(QUEUE_SIZE)],
            queue_evts,
            block_tracker: None,
        })
    }

    pub fn attach_block_tracker(
        &mut self,
        block_tracker: Arc<Mutex<MemoryBlockTracker>>,
    ) -> Result<(), MemoryError> {
        self.block_tracker = Some(block_tracker);

        Ok(())
    }

    /// Process device virtio queue.
    pub fn process_guest_requests(&mut self) -> Result<(), MemoryError> {
        debug!("Memory.process_guest_requests_queue");
        let device_id = String::from(self.id().clone());

        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();
        let queue = &mut self.queues[GUEST_REQUESTS_INDEX];
        let mut needs_signal = false;

        while let Some(head) = queue.pop(mem) {
            if head.is_write_only() {
                // all requests from the driver should be read only
                return Err(MemoryError::MalformedDescriptor);
            }

            let len = head.len as usize;
            debug!(
                "Got a descriptor chain with length [{}] and index [{}] has_next [{}]",
                len,
                head.index,
                head.has_next(),
            );

            if len != std::mem::size_of::<MemoryRequest>() {
                return Err(MemoryError::MalformedDescriptor);
            }

            let request = mem
                .read_obj::<MemoryRequest>(head.addr)
                .map_err(|_| MemoryError::MalformedDescriptor)?;

            debug!("[Memory] got a request [{:?}]", request);

            match request.req_type {
                VIRTIO_MEM_REQ_PLUG => {
                    debug!(
                        "[Memory][{}] got a PLUG request .. doing nothing and ACK back ;) .. 
                          i guess",
                        device_id
                    );

                    let requested_size = request.nb_blocks as u64 * self.config_space.block_size;

                    if let Some(next_descriptor_chain) = head.next_descriptor() {
                        debug!("this is the descriptor the device has to write into");
                        debug!(
                            "this descriptor is write only [{}] has_next [{}]",
                            next_descriptor_chain.is_write_only(),
                            next_descriptor_chain.has_next(),
                        );

                        let block_tracker = self
                            .block_tracker
                            .as_ref()
                            .expect("Memory device broken state");

                        let result = block_tracker
                            .lock()
                            .expect("Poisoned lock")
                            .plug_blocks(request.addr, request.nb_blocks as u64);

                        let resp;

                        match result {
                            Ok(_) => {
                                debug!("Plugged successs!!!!!!!");
                                self.config_space.plugged_size += requested_size;
                                resp = MemoryResponse::new().ack();
                            }
                            Err(err) => {
                                debug!("Encountered error when pluggin {:?}", err);
                                resp = MemoryResponse::new().nack();
                            }
                        }

                        mem.write_obj(resp, next_descriptor_chain.addr)
                            .map_err(MemoryError::WriteResponse)?;

                        queue
                            .add_used(
                                mem,
                                head.index,
                                std::mem::size_of::<MemoryResponse>().try_into().unwrap(),
                            )
                            .map_err(MemoryError::Queue)?;
                        needs_signal = true;
                    }
                }
                _ => {
                    unimplemented!("Virtio-mem unimplemented request type")
                }
            }
            // MemTotal:        8155232 kB
            // MemFree:         8082132 kB
            // MemAvailable:    7960396 kB

            // ---
            // MemTotal:        8155232 kB
            // MemFree:         8085668 kB
            // MemAvailable:    7963924 kB

            // ---
            // MemTotal:        1006564 kB
            // MemFree:          949256 kB
            // MemAvailable:     891980 kB
            // panic!("STOP");

            // plugged size:   0x48000000
            // requested size: 0x200000000
        }

        if needs_signal {
            self.signal_used_queue()?;
        }

        Ok(())
    }

    pub fn process_guest_request_queue(&mut self) -> Result<(), MemoryError> {
        self.queue_evts[GUEST_REQUESTS_INDEX]
            .read()
            .map_err(MemoryError::EventFd)?;
        self.process_guest_requests()
    }

    #[inline]
    fn addr_is_set(&self) -> bool {
        self.addr_is_set
    }

    /// Set the start address of the memory region managed by this device.
    pub fn set_addr(&mut self, addr: u64) -> Result<(), MemoryError> {
        if self.addr_is_set() {
            return Err(MemoryError::AddressAlreadySet);
        }
        self.config_space.addr = addr;
        self.addr_is_set = true;

        Ok(())
    }

    /// Retrieves the base address of the memory device if set.
    pub fn get_addr(&self) -> Option<u64> {
        if self.addr_is_set {
            Some(self.config_space.addr)
        } else {
            None
        }
    }

    /// Resturns the identifier of the device.
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns the region size (in Bytes) of the device.
    pub fn region_size(&self) -> u64 {
        self.config_space.region_size
    }

    /// Returns the block size (in Bytes) of the device.
    pub fn block_size(&self) -> u64 {
        self.config_space.block_size
    }

    pub(crate) fn signal_used_queue(&self) -> Result<(), MemoryError> {
        self.irq_trigger
            .trigger_irq(IrqType::Vring)
            .map_err(MemoryError::InterruptError)
    }

    /// Handle
    pub fn change_requested_size(&mut self, requested_size: u64) -> Result<(), MemoryError> {
        // TODO
        info!(
            "Got a request to change the requested_size of memory device [{}] to [{}] bytes",
            self.id(),
            requested_size
        );

        Ok(())
    }
}

impl VirtioDevice for Memory {
    fn device_type(&self) -> u32 {
        TYPE_MEMORY
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.irq_trigger.irq_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.irq_trigger.irq_status.clone()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }

        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &config_space_bytes[offset as usize..cmp::min(end, config_len) as usize],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        debug!("[MEMORY][write_config]");
        let data_len = data.len() as u64;
        let config_space_bytes = self.config_space.as_mut_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        config_space_bytes[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Memory: Cannot write to activate_evt");
            // TODO: Increment metrics (?)
            self.device_state = DeviceState::Inactive;
            return Err(super::super::ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem);
        info!("Memory device [{}] got activated!", self.id());

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use utils::{byte_order, get_page_size};
    use virtio_gen::virtio_blk::VIRTIO_F_VERSION_1;
    use vm_memory::ByteValued;

    use super::super::CONFIG_SPACE_SIZE;
    use super::{Memory, MemoryError, TYPE_MEMORY};
    use crate::virtio::memory::device::ConfigSpace;
    use crate::virtio::{Queue, VirtioDevice};

    impl Memory {
        pub(crate) fn set_queue(&mut self, idx: usize, q: Queue) {
            self.queues[idx] = q;
        }
    }

    fn page_size() -> u64 {
        get_page_size().unwrap() as u64
    }

    #[test]
    fn test_new_memory() {
        let page_size: u64 = page_size();

        let block_size_zero = Memory::new(0, None, 0, String::from("memory-dev-1"));
        match block_size_zero {
            Err(MemoryError::BlockSizeIsZero) => {}
            _ => unreachable!(),
        }

        let block_size_allignment =
            Memory::new(page_size + 1, None, 0, String::from("memory-dev-2"));
        match block_size_allignment {
            Err(MemoryError::BlockSizeNotMultipleOfPageSize(_)) => {}
            _ => unreachable!(),
        }

        let block_size_power2 = Memory::new(page_size * 3, None, 0, String::from("memory-dev-3"));
        match block_size_power2 {
            Err(MemoryError::BlockSizeNotPowerOf2) => {}
            _ => unreachable!(),
        }

        let region_size_multiple =
            Memory::new(page_size, None, page_size + 1, String::from("memory-dev-4"));
        match region_size_multiple {
            Err(MemoryError::SizeNotMultipleOfBlockSize) => {}
            _ => unreachable!(),
        }

        let memory_ok =
            Memory::new(page_size, None, page_size, String::from("memory-dev-5")).unwrap();
        assert_eq!(memory_ok.device_type(), TYPE_MEMORY);
        assert_eq!(memory_ok.id(), "memory-dev-5");
        assert!(!memory_ok.addr_is_set());
        assert_eq!(memory_ok.acked_features(), 0);
        assert_eq!(memory_ok.avail_features(), 1u64 << VIRTIO_F_VERSION_1);
        assert_eq!(memory_ok.block_size(), page_size);
        assert_eq!(memory_ok.region_size(), page_size);
    }

    #[test]
    fn test_read_config() {
        let page_size: u64 = get_page_size().unwrap() as u64;
        let memory_device =
            Memory::new(page_size, None, page_size, String::from("memory-dev")).unwrap();

        // 7 fields of 8 Bytes each
        let mut actual_config_space = [0u8; CONFIG_SPACE_SIZE];

        memory_device.read_config(0, &mut actual_config_space);
        // pub block_size: u64,
        assert_eq!(
            byte_order::read_le_u64(&actual_config_space[..8]),
            page_size
        );
        // pub node_id: u16,
        assert_eq!(byte_order::read_le_u16(&actual_config_space[8..10]), 0u16);
        // _padding: [u8; 6],
        assert_eq!(&actual_config_space[10..16], [0u8; 6]);
        // pub addr: u64,
        assert_eq!(byte_order::read_le_u64(&actual_config_space[16..24]), 0u64);
        // pub region_size: u64,
        assert_eq!(
            byte_order::read_le_u64(&actual_config_space[24..32]),
            page_size
        );
        // pub usable_region_size: u64,
        assert_eq!(byte_order::read_le_u64(&actual_config_space[32..40]), 0u64);
        // pub plugged_size: u64,
        assert_eq!(byte_order::read_le_u64(&actual_config_space[40..41]), 0u64);
        // pub requested_size: u64,
        assert_eq!(
            byte_order::read_le_u64(&actual_config_space[48..CONFIG_SPACE_SIZE]),
            0u64
        );
    }

    #[test]
    fn test_write_config() {
        let page_size: u64 = get_page_size().unwrap() as u64;
        let mut memory_device =
            Memory::new(page_size, None, page_size, String::from("memory-dev")).unwrap();

        let mut expected_config_space: [u8; CONFIG_SPACE_SIZE] = [0u8; CONFIG_SPACE_SIZE];

        // reading the expected config is assured by `test_read_config()`
        memory_device.read_config(0, &mut expected_config_space);

        // this write should fail to write
        let garbage_config_space = [0xffu8; CONFIG_SPACE_SIZE];
        memory_device.write_config(3, &garbage_config_space);

        // reading again
        let mut actual_config_space = [0xffu8; CONFIG_SPACE_SIZE];
        memory_device.read_config(0, &mut actual_config_space);

        // this write should go through setting every bit
        memory_device.write_config(0, &garbage_config_space);

        memory_device.read_config(0, &mut actual_config_space);
        assert_eq!(garbage_config_space, actual_config_space);

        // now construction of a valid config space
        let config_space = ConfigSpace {
            block_size: page_size * 2,
            node_id: 0,
            _padding: [0u8; 6],
            addr: 0,
            region_size: page_size * 8,
            usable_region_size: 0,
            plugged_size: 0,
            requested_size: 0,
        };

        // Writing should go through
        let new_config_space = config_space.as_slice();
        memory_device.write_config(0, &new_config_space);

        assert_eq!(memory_device.block_size(), page_size * 2);
        assert_eq!(memory_device.region_size(), page_size * 8);
    }
}
