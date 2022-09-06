// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::io::Write;
use std::result::Result;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use logger::{error, info};
use utils::{eventfd::EventFd, get_page_size};
use virtio_gen::virtio_blk::VIRTIO_F_VERSION_1;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_MEMORY};
use super::QUEUE_SIZE;
use crate::virtio::memory::Error as MemoryError;

use crate::virtio::IrqTrigger;

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
}

impl Memory {
    pub fn new(
        block_size: u64,
        node_id: Option<u16>,
        region_size: u64,
        id: String,
    ) -> Result<Memory, MemoryError> {
        // memory device is only available for 64 bit platforms
        let page_size: u64 = get_page_size().map_err(MemoryError::PageSize)? as u64;

        if block_size % page_size != 0 {
            return Err(MemoryError::BlockSizeNotAllignedToPage);
        }

        // virtio-mem spec requirement
        if !block_size.is_power_of_two() {
            return Err(MemoryError::BlockSizeNotPowerOf2);
        }

        // virtio-mem spec requirement
        if region_size % block_size != 0 {
            return Err(MemoryError::SizeNotMultipleOfBlockSize);
        }

        let avail_features = 1u64 << VIRTIO_F_VERSION_1;

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(MemoryError::EventFd)?];

        if let Some(node_id) = node_id {
            todo!("Node id feature unimplemented [{}]", node_id);
        }

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
                usable_region_size: 0u64,
                plugged_size: 0u64,
                requested_size: 0u64,
            },
            id,
            irq_trigger: IrqTrigger::new().map_err(MemoryError::EventFd)?,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(MemoryError::EventFd)?,
            queues: [Queue::new(QUEUE_SIZE)],
            queue_evts,
        })
    }

    /// Process device virtio queue.
    pub fn process_guest_request_queue(&mut self) {
        // TODO
        info!("Memory.process_guest_requests_queue");
    }

    fn addr_is_set(&self) -> bool {
        self.addr_is_set
    }

    /// Set the start address of the memory region managed by this device.
    pub fn set_addr(&mut self, addr: u64) -> Result<(), MemoryError> {
        if self.addr_is_set() {
            return Err(MemoryError::AddressAlreadySet);
        }
        self.config_space.addr = addr;

        Ok(())
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
        self.device_state = DeviceState::Activated(mem);
        if self.activate_evt.write(1).is_err() {
            error!("Memory: Cannot write to activate_evt");
            // TODO: Increment metrics (?)
            self.device_state = DeviceState::Inactive;
            return Err(super::super::ActivateError::BadActivate);
        }

        info!("Memory device [{}] got activated!", self.id());

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {}
