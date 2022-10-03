// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vm_memory_upstream::bitmap::AtomicBitmap;
use vm_memory_upstream::mmap::{Error as GuestMemoryMmapError, Iter as GuestMemoryIter};
use vm_memory_upstream::{Address, AddressValue, GuestAddress, GuestMemory, GuestMemoryRegion};

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
}

/// A wrapper over upstream GuestMemoryMmap.
#[derive(Debug, Clone)]
pub struct GuestMemoryMmap {
    // Original `guest_memory`; Once constructed this should never be modified.
    mmap: GuestMemoryMmapUpstream<Option<AtomicBitmap>>,

    // Information about the state of each regions. Memory regions have unique
    // start addresses so the key is `guest_base` of a `GuestRegionMmap`.
    state: Arc<Mutex<HashMap<u64, RegionState>>>,
}

/// implementing the `GuestMemory` for our wrapper structure over the upstream
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
}

/// Implementing methods for creating `GuestMemoryMmap`.
impl GuestMemoryMmap {
    /// This creates a `GuestMemoryMmap` without knowing which of the regions are provided
    /// by memory devices.
    pub fn from_regions(regions: Vec<GuestRegionMmap>) -> Result<Self, GuestMemoryMmapError> {
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
}
