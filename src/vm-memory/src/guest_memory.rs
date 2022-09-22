// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use vm_memory_upstream::bitmap::{AtomicBitmap, Bitmap};
use vm_memory_upstream::mmap::{Error as GuestMemoryMmapError, Iter as GuestMemoryIter};
use vm_memory_upstream::{Address, GuestAddress, GuestMemory, GuestMemoryRegion};

// using this ugly name so we can export `GuestMemoryMmap` internally
type GuestMemoryMmapUpstream<B> = vm_memory_upstream::GuestMemoryMmap<B>;
pub type GuestRegionMmap = vm_memory_upstream::GuestRegionMmap<Option<AtomicBitmap>>;
pub type GuestMmapRegion = vm_memory_upstream::MmapRegion<Option<AtomicBitmap>>;

/// State of a regions with respect to how the property of accessibility changes.
#[derive(Debug)]
enum RegionState {
    /// All memory in this region is accessible. Nothing will change this.
    Fixed,
    /// Memory accessibility can change at any time. It is being tracked
    /// at block (not to be confused with `page`) granularity by e memory device.
    Volatile(Arc<Mutex<MemoryBlockTracker>>),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Provided address is the base address of a fixed region.
    #[error("Provided address is the base address of a fixed region.")]
    AddressBaseOfFixedRegion,
    /// Provided address is not the base address of any region.
    #[error("Provided address is not the start addresss of any region.")]
    AddressNotBaseOfRegion,
    /// Memory region with this base address already exists.
    #[error("Duplicate base address: {0}")]
    DuplicateBaseAddress(u64),
    /// Error related to the creation of a memory map.
    #[error("{0}")]
    GuestMemoryMmap(#[from] GuestMemoryMmapError),
    /// Regions order is broken.
    #[error("Normal region detected after memory device region")]
    NormalRegionAfterDeviceRegion,
    /// Block tracker not found.
    #[error("No block tracker associated with device \"{0}\"")]
    TrackerNotFound(String),
}

#[derive(Debug, thiserror::Error)]
pub enum TrackerError {
    /// Address is not the base address of a block within the region.
    #[error("Address is not the base address of a block within the region.")]
    AddressNotBaseOfBlock,
    /// Provided (absolute) address is outside of memory region.
    #[error("Provided address is outside of memory region.")]
    AddressOutsideOfRegion,
    /// Operation performed on a set of blocks that are not all present inside the
    /// memory region.
    #[error("Some blocks are outside of the memory region.")]
    BlocksOutsideOfRegion,
    /// Error encountered while trying to change the access rights of the region.
    #[error("Error while changing protection of region: {0}")]
    ChangeAccessRights(#[from] io::Error),
    /// The memory blocks don't all have the same state (plugged/unplugged).
    #[error("Not all memoyr blocks are (un)plugged.")]
    InconsistentInternalState,
}

/// Structure that tracks the validity of memory blocks inside a memory region.
/// The memory region is a contiguous physical address range inside the
/// guests' memory so it cannot have holes.
///
/// Valid block = Memory is backed by the VMM in some way (e.g. `mmap`ed into the
/// process, this is granted by upstream mmap implementation)
///     AND
/// The memory that backes is SAFE to R/W by the VMM (and susequently by the guest).
/// (it is `mmap`ed with Read/Write rights)
///
/// Invalid block = Memory is still backed by the VMM, but the guest can't access it.
/// And neither should the VMM!!! (e.g. `mmap`ed memory without access rights)
///
/// Only memory devices will use this structure.
#[derive(Clone, Debug)]
pub struct MemoryBlockTracker {
    // A reference to the memory region it tracks. Usefull especially for
    // the memory devices themselves that need to access the raw pointer.
    memory_region: Arc<GuestRegionMmap>,

    // Structure to track if the blocks are valid
    // Should only be modified by the owning memory device.
    bitmap: AtomicBitmap,

    // `bitmap` does not expose `page_size` so we need to keep `block_size` ourselves.
    block_size: u64,

    // Cache for the last valid address. It is always up-to-date. It's easier to update
    // it when hot(un)plugging than to traverse the bitmap.
    // `None` signifies no actual last address -> no memory provided.
    last_addr: Option<GuestAddress>,
}

fn change_access_rights(
    region: Arc<GuestRegionMmap>,
    offset: u64,
    len: usize,
    new_prot: i32,
) -> Result<(), io::Error> {
    let region_base_ptr = region.as_ptr();
    let mut addr = unsafe { region_base_ptr.add(offset as usize) } as *mut libc::c_void;
    // Memory is not backed by a file.
    let flags = libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS; // | libc::MAP_NORESERVE;

    addr = unsafe { libc::mmap(addr, len, new_prot, flags, -1, 0) };

    if addr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

impl MemoryBlockTracker {
    pub fn new(memory_region: Arc<GuestRegionMmap>, block_size: usize) -> Self {
        let region_size = memory_region.size();
        let bitmap = AtomicBitmap::new(region_size, block_size);
        MemoryBlockTracker {
            memory_region,
            bitmap,
            block_size: block_size as u64,
            last_addr: None,
        }
    }

    /// Hotplugs memory blocks starting with (absolute) address provided.
    ///
    /// Only performs the action if all the blocks correspond to this memory region and none
    /// of them are already plugged.
    pub fn plug_blocks(
        &mut self,
        block_start_addr: u64,
        nr_blocks: u64,
    ) -> Result<(), TrackerError> {
        let start_block_index;
        let block_offset_addr;

        match self
            .memory_region
            .to_region_addr(GuestAddress::new(block_start_addr))
        {
            Some(offset) => {
                // Provided address does not correspond to the start of a block inside
                // this region. Returning error so that caller can report furter.
                if offset.raw_value() % self.block_size != 0 {
                    return Err(TrackerError::AddressNotBaseOfBlock);
                }

                start_block_index = offset.raw_value() / self.block_size;
                let last_block_index = start_block_index + nr_blocks;

                // Is the index of the last block we want to operate on is bigger than
                // the total number of blocks this regions has?

                // Example
                // region:          [0, 1, 2, 3, 4, 5, 6, 7] -> 8 blocks
                // start_block_index = 3 -----^           ^
                // nr_blocks = 5              |           |
                // blocks covered:            |-----------|   (3, 4, 5, 6, 7)
                // This is valid, but with `nr_blocks` = 6 it would overflow.
                if last_block_index > (self.bitmap.len() as u64) {
                    return Err(TrackerError::BlocksOutsideOfRegion);
                }

                block_offset_addr = offset;

                if (start_block_index..=last_block_index)
                    .into_iter()
                    .map(|index| self.bitmap.is_bit_set(index as usize))
                    .any(|res| res)
                {
                    return Err(TrackerError::InconsistentInternalState);
                }
            }
            None => {
                return Err(TrackerError::AddressOutsideOfRegion);
            }
        }

        // Checks performed so now we know that the block start address is a valid and
        // all of them are unplugged.

        let len = (nr_blocks * self.block_size) as usize;

        change_access_rights(
            self.memory_region.clone(),
            block_offset_addr.raw_value(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
        )?;

        self.bitmap
            .mark_dirty(block_offset_addr.raw_value() as usize, len);

        // TODO: update last address;

        Ok(())
    }

    /// Retrieves the last (inclusive) valid address tracked.
    fn last_addr(&self) -> Option<GuestAddress> {
        self.last_addr
    }

    /// Checks whether an addres is valid inside the tracked region.
    fn addr_is_valid(&self, addr: GuestAddress) -> bool {
        match self.memory_region.to_region_addr(addr) {
            Some(offset) => self.bitmap.is_addr_set(offset.raw_value() as usize),
            None => false,
        }
    }
}

/// A wrapper over upstream GuestMemoryMmap.
///
/// All `Device`-backed regions come after all `Normal` regions.
#[derive(Debug, Clone)]
pub struct GuestMemoryMmap {
    // Original `guest_memory`; Once constructed this should never be modified.
    mmap: GuestMemoryMmapUpstream<Option<AtomicBitmap>>,

    // Information about the state of each regions. Memory regions have unique
    // start addresses so the key is `guest_base` of a `GuestRegionMmap`.
    state: Arc<Mutex<HashMap<u64, RegionState>>>,
}

/// Implementing the `GuestMemory` for our wrapper structure over the upstream
/// `GuestMemoryMmap` by using the implemented upstream methods (for now).
///
/// Methods `num_regions`, `find_region` and `iter` do not have a default
/// implementation. Implementing these methods needs a bit of thinking because
/// other alredy implemented methods might be based on how these behave.
/// Since we're introducing some regions that will have a special behaviour
/// (hot(un)pluggind, thus modifying how much memory we have)
/// we need to make sure we don't break the overall functionality.
///
/// - `num_regions`: returns the number of regions including the regions provided by the memory
///   device. It is not used anywhere else in the implementation of other methods (inside the trait
///   and inside the`GuestMemoryMmapUpstream`). It can passthrough.
///
/// - `find_region`: many of the other methods use this in their default implementation, and then
///   many more methods use those methods as well (including reading and writing to the memory!!!)
///   so changing this will have (very) big consequences. We will change the default implementation
///   of the methods that use this one as needed. It will passthrough.
///
/// - `iter`: this is only used to compute `last_addr`. It will passthrough.
///
/// Other overridden methods:
/// - `last_addr`: it now returns the last (inclusive) address that is exposed as normal RAM.
/// The reason for this is that this method is used when setting up the system and telling the
/// guest OS how much (non virtio-mem) memory it has.
impl GuestMemory for GuestMemoryMmap {
    type R = GuestRegionMmap;
    type I = GuestMemoryMmapUpstream<Option<AtomicBitmap>>;

    fn num_regions(&self) -> usize {
        self.mmap.num_regions()
    }

    fn find_region(&self, addr: GuestAddress) -> Option<&Self::R> {
        self.mmap.find_region(addr)
    }

    fn iter(&self) -> GuestMemoryIter<'_, Option<AtomicBitmap>> {
        self.mmap.iter()
    }

    fn address_in_range(&self, addr: GuestAddress) -> bool {
        // First we use the underlying implementation to see if the address is inside a
        // a `GuestRegionMmap` region.
        if !self.mmap.address_in_range(addr) {
            return false;
        }

        // Previous check made sure the address belongs to a region.
        let region = self
            .mmap
            .find_region(addr)
            .expect("Memory broken internal state.");

        let base_addr = region.start_addr().raw_value();
        let locked_state = self.state.lock().expect("Poisoned lock");

        // Base address was retrieved from a valid region.
        let region_state = locked_state
            .get(&base_addr)
            .expect("Memory broken internal state.");

        match region_state {
            RegionState::Fixed => true,
            RegionState::Volatile(tracker) => {
                tracker.lock().expect("Poisoned lock").addr_is_valid(addr)
            }
        }
    }

    /// Return the last (inclusive) address.
    fn last_addr(&self) -> GuestAddress {
        // Iterator implementation does not support `rev()`.
        self.iter()
            .map(|region| {
                let base_addr = region.start_addr().raw_value();
                let locked_state = self.state.lock().expect("Poisoned lock");

                let region_state = locked_state
                    .get(&base_addr)
                    .expect("GuestMemory broker internal state");

                match region_state {
                    RegionState::Fixed => Some(region.last_addr()),
                    RegionState::Volatile(tracker) => {
                        tracker.lock().expect("Poisoned lock").last_addr()
                    }
                }
            })
            .fold(GuestAddress::new(0), |acc, next| match next {
                Some(addr) => std::cmp::max(acc, addr),
                None => acc,
            })
    }
}

/// Wrapper structure to avoid passing tuples.
pub(crate) struct Region(Arc<GuestRegionMmap>, Option<usize>);

impl Region {
    pub fn new(region: Arc<GuestRegionMmap>, info: Option<usize>) -> Self {
        Region(region, info)
    }
}

/// Implementing methods for creating `GuestMemoryMmap`.
impl GuestMemoryMmap {
    /// This creates a `GuestMemoryMmap` without knowing which of the regions are provided
    /// by memory devices.
    pub fn from_regions(regions: Vec<GuestRegionMmap>) -> Result<Self, Error> {
        let mmap = GuestMemoryMmapUpstream::from_regions(regions)?;
        let mut state = HashMap::new();

        for region in mmap.iter() {
            let base_addr = region.start_addr().raw_value();

            // `mmap` creation assures correct regions.
            assert!(state.insert(base_addr, RegionState::Fixed).is_none());
        }

        Ok(Self {
            mmap,
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// This creates a `GuestMemoryMmap` by knowing from the start who provides/manages
    /// the memory regions.
    ///
    /// Caller must make sure all the `Normal` regions are placed before any `Device` region
    /// and that all the regions are ordered and do not overlap.
    pub(crate) fn new(regions: Vec<Region>) -> Result<Self, Error> {
        // Checking to see if there's a `Normal` region after a `Device` one as
        // that should not happen.
        let mut device_present = false;
        let mut state = HashMap::new();

        // The vec of memory regions that we'll pass to upstream `from_arc_regions`.
        let mut mmap_regions = Vec::with_capacity(regions.len());

        for region in regions {
            let (region_mmap, device_info) = (region.0, region.1);
            let base_addr = region_mmap.start_addr().raw_value();
            let region_state;

            if let Some(block_size) = device_info {
                // Got a device. If we see a `Normal` region from now on we throw an error.
                device_present = true;

                let block_tracker = Arc::new(Mutex::new(MemoryBlockTracker::new(
                    region_mmap.clone(),
                    block_size,
                )));

                region_state = RegionState::Volatile(block_tracker);
            } else {
                region_state = RegionState::Fixed;

                if device_present {
                    return Err(Error::NormalRegionAfterDeviceRegion);
                }
            }
            // If `trackers` already had an entry for this device the caller is at fault.
            if state.insert(base_addr, region_state).is_some() {
                return Err(Error::DuplicateBaseAddress(base_addr));
            };
            mmap_regions.push(region_mmap);
        }

        Ok(Self {
            mmap: GuestMemoryMmapUpstream::from_arc_regions(mmap_regions)?,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn get_block_tracker(
        &self,
        base_addr: u64,
    ) -> Result<Arc<Mutex<MemoryBlockTracker>>, Error> {
        match self.state.lock().expect("Poisoned lock").get(&base_addr) {
            Some(RegionState::Fixed) => Err(Error::AddressBaseOfFixedRegion),
            Some(RegionState::Volatile(tracker)) => Ok(tracker.clone()),
            None => Err(Error::AddressNotBaseOfRegion),
        }
    }
}
