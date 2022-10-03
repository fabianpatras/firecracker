// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vm_memory_upstream::bitmap::AtomicBitmap;
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

    // Cache for the last valid address. It is always up-to-date. It's easier to update
    // it when hot(un)plugging than to traverse the bitmap.
    // `None` signifies no actual last address -> no memory provided.
    last_addr: Option<GuestAddress>,
}

impl MemoryBlockTracker {
    pub fn new(memory_region: Arc<GuestRegionMmap>, block_size: usize) -> Self {
        let region_size = memory_region.size();
        let bitmap = AtomicBitmap::new(region_size, block_size);
        MemoryBlockTracker {
            memory_region,
            bitmap,
            last_addr: None,
        }
    }
}

impl MemoryBlockTracker {
    /// Retrieves the last (inclusive) valid address tracked.
    fn last_addr(&self) -> Option<GuestAddress> {
        self.last_addr
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

        // TODO: Here comes the logic for when the address is inside the memory regions,
        // but we still need to check if the address is valid based on who provides that region.
        true
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
            let (region, device_info) = (region.0, region.1);
            let base_addr = region.start_addr().raw_value();
            let region_state;

            if let Some(block_size) = device_info {
                // Got a device. If we see a `Normal` region from now on we throw an error.
                device_present = true;

                let block_tracker = Arc::new(Mutex::new(MemoryBlockTracker::new(
                    region.clone(),
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
            mmap_regions.push(region);
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
